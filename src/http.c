#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "proxy.h"
#include "skcomm.h"

enum {
    PHASE_SEND_REQUEST = 1,
    PHASE_RECV_REPLY,
    PHASE_FORWARDING
};

static const char *phasestr[] = {
    [PHASE_SEND_REQUEST] = "PHASE_SEND_REQUEST",
    [PHASE_RECV_REPLY] = "PHASE_RECV_REPLY",
    [PHASE_FORWARDING] = "PHASE_FORWARDING",
};

/* Base64 output length (include NUL terminate) */
#define BASE64_OUTLEN(inlen) (((inlen) + 2) / 3 * 4 + 1)

/* Base64 encoding table */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode function
   Returns the number of bytes written to output (include NUL terminate)
*/
static size_t base64_encode(char *output, size_t outlen,
                            const void *binary, size_t inlen)
{
    size_t i, j;

    if (inlen > (SIZE_MAX - 1) / 4 * 3 || outlen < ((inlen + 2) / 3) * 4 + 1)
        return 0;

    for (i = 0, j = 0; i < inlen;) {
        unsigned char a3[3] = { 0 };
        unsigned char a4[4];
        size_t k;

        for (k = 0; k < 3 && i < inlen; k++)
            a3[k] = ((unsigned char *)binary)[i++];

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) | (a3[1] >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) | (a3[2] >> 6);
        a4[3] = a3[2] & 0x3f;

        output[j++] = base64_chars[a4[0]];
        output[j++] = base64_chars[a4[1]];
        output[j++] = k > 1 ? base64_chars[a4[2]] : '=';
        output[j++] = k > 2 ? base64_chars[a4[3]] : '=';
    }

    output[j++] = '\0';
    return j;
}

struct proxy_http {
    struct proxy ops;
    struct sk_comm comm;
    userev_fn_t *userev;
    void *userp;
    char *addr; /* for proxied connection, not proxy server */
    uint16_t port;
    int phase;
    /* for handshake only */
    char buffer[512];
    ssize_t nbuffer;
    int refcnt;
};

static void http_handshake_perror(struct proxy_http *self, int err)
{
    if (err > 0)
        loglv(0, "Proxy server reset unexpectedly during HTTP handshake "
                 "phase [%s]: %s", phasestr[self->phase], strerror(err));
    else
        loglv(0, "Proxy server closed unexpectedly during HTTP handshake "
                 "phase [%s]", phasestr[self->phase]);
}

/* epoll event callback
   used of receiving http response */
static void http_handshake_input(struct proxy_http *self)
{
    ssize_t nread;
    char *crlf2;
    ssize_t ndiscard;
    char vermin;
    int code;

    /* Use MSG_PEEK here, if some application layer data has been returned,
       we can carefuly not to touch them
       Treat self->buffer as string, nerver forget set a '\0' after recv()
    */
    nread = recv(self->comm.sfd, self->buffer + self->nbuffer,
                 sizeof(self->buffer) - self->nbuffer - 1, MSG_PEEK);
    if (nread <= 0) {
        if (nread == 0 || errno != EAGAIN) {
            http_handshake_perror(self, nread == -1 ? errno : 0);
            self->userev(self->userp, ~0u);
        }
        return;
    }
    (self->buffer + self->nbuffer)[nread] = '\0';

    /* serch from start every time, servers (who?) may trim \r\n\r\n */
    crlf2 = strstr(self->buffer, "\r\n\r\n");

    /* number of bytes need to discard after recv(..., MSG_PEEK) */
    ndiscard = crlf2
        ? (crlf2 + strlen("\r\n\r\n") - (self->buffer + self->nbuffer))
        : nread;

    /* discard http response part in socket buffer */
    nread = recv(self->comm.sfd, self->buffer + self->nbuffer, ndiscard, 0);
    if (nread != ndiscard) {
        fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, ndiscard);
        abort();
    }
    self->nbuffer += ndiscard;

    /* handshake not finished */
    if (!crlf2) {
        /* failed, handshake not finished but buffer full */
        if (self->nbuffer == sizeof(self->buffer) - 1) {
            loglv(0, "Proxy server returned a header that is too large "
                     "during the handshake.");
            self->userev(self->userp, ~0u);
        }
        /* if not failed, wait for rest handshake message */
        return;
    }

    /* check response */
    if (sscanf(self->buffer, "HTTP/1.%c %d", &vermin, &code) != 2) {
        loglv(0, "Proxy server returned invalid HTTP response header during "
                 "handshake");
        self->userev(self->userp, ~0u);
        return;
    }
    if (code != 200) {
        if (code == 407 || code == 401) {
            loglv(0, "Proxy authentication failed (HTTP %d). "
                     "Please check your username and password.", code);
        } else {
            loglv(0, "Proxy server returned HTTP error %d", code);
        }
        self->userev(self->userp, ~0u);
        return;
    }

    self->phase = PHASE_FORWARDING;
    loglv(1, "Connected %s:%u/tcp", self->addr, (unsigned)self->port);

    /* good, handshake finish, listen and forward epoll event for user */
    self->comm.events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_MOD, self->comm.sfd,
                   self->comm.events, &self->comm.epcb);
}

/* epoll event callback
   used of sending http request */
static void http_handshake_output(struct proxy_http *self)
{
    ssize_t nsent;

    /* it's first called to this function, assembly request */
    if (!self->nbuffer) {
        if (strlen(current_nspconf()->proxyuser)) {
            char credentials[AUTH_MAXLEN * 2 + 1 + 1];
            char base64[BASE64_OUTLEN(AUTH_MAXLEN * 2 + 1)];
            snprintf(credentials, sizeof(credentials), "%s:%s",
                     current_nspconf()->proxyuser, current_nspconf()->proxypass);
            base64_encode(base64, sizeof(base64), credentials, 
                          strlen(credentials));
            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                                     "CONNECT %s:%u HTTP/1.1"        "\r\n"
                                     "Host: %s:%u"                   "\r\n"
                                     "Proxy-Authorization: Basic %s" "\r\n"
                                     "\r\n",
                                     self->addr, (unsigned int)self->port,
                                     self->addr, (unsigned int)self->port,
                                     base64);
        } else {
            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                                     "CONNECT %s:%u HTTP/1.1" "\r\n"
                                     "Host: %s:%u"            "\r\n"
                                     "\r\n",
                                     self->addr, (unsigned int)self->port,
                                     self->addr, (unsigned int)self->port);
        }
    }

    nsent = send(self->comm.sfd, self->buffer,self->nbuffer, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno != EAGAIN) {
            http_handshake_perror(self, errno);
            self->userev(self->userp, ~0u);
        }
        return;
    }
    self->nbuffer -= nsent;

    if (self->nbuffer != 0) {
        /* partial write, wait next time to write rest */
        memmove(self->buffer, self->buffer + nsent, self->nbuffer);
        return;
    }

    /* good, http request has been send */
    self->phase = PHASE_RECV_REPLY;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_MOD, self->comm.sfd, EPOLLIN,
                   &self->comm.epcb);
}

static void http_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct sk_comm *comm = container_of(epcb, struct sk_comm, epcb);
    struct proxy_http *self = container_of(comm, struct proxy_http, comm);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events);
        return;
    }

    loglv(3, "http_epcb_events: handshaking with %s:%u/tcp [%s]",
             self->addr, (unsigned)self->port, phasestr[self->phase]);

    if (self->phase == PHASE_SEND_REQUEST) {
        http_handshake_output(self);
    } else {
        http_handshake_input(self);
    }
}

/* impl for struct proxy :: shutdown */
static int http_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return skcomm_common_shutdown(&self->comm, how, rst);
}

/* impl for struct proxy :: evctl */
static void http_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);

    if (self->phase != PHASE_FORWARDING)
        return;

    skcomm_common_evctl(&self->comm, event, enable);
}

/* impl for struct proxy :: send */
static ssize_t http_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    return skcomm_common_send(&self->comm, data, size);
}

/* impl for struct proxy :: recv */
static ssize_t http_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    return skcomm_common_recv(&self->comm, data, size);
}

/* impl for struct proxy :: get */
static void http_get(struct proxy *proxy)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    self->refcnt++;
}

/* impl for struct proxy :: put */
static void http_put(struct proxy *proxy)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    if (--self->refcnt == 0) {
        skcomm_common_close(&self->comm);
        free(self->addr);
        free(self);
    }
}

/* global vtable of proxy_http */
static const struct proxy_ops http_ops = {
    .shutdown = &http_shutdown,
    .evctl = &http_evctl,
    .send = &http_send,
    .recv = &http_recv,
    .get = &http_get,
    .put = &http_put,
};

/* create a tcp connection
   this connection is proxied via http proxy server */
struct proxy *http_tcp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *addr, uint16_t port)
{
    struct proxy_http *self;
    struct nspconf *conf = current_nspconf();

    loglv(3, "http_tcp_create: creating a new struct conn_http");

    if ((self = calloc(1, sizeof(struct proxy_http))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->ops.ops = &http_ops;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    self->comm.epcb.on_epoll_events = &http_epcb_events;
    self->comm.loop = loop;
    self->comm.stype = SOCK_STREAM;
    self->comm.sfd = -1;

    /* perform connect */
    loglv(3, "http_tcp_create: connecting %s:%u/tcp", addr, (unsigned)port);

    if (strlen(addr) >= SERVNAME_MAXLEN) {
        free(self);
        return NULL;
    }

    /* connect to proxy server */
    if (skcomm_common_connect(&self->comm,
                              conf->proxysrv, conf->proxyport) != 0) {
        free(self);
        return NULL;
    }

    /* good, start handshake */
    self->phase = PHASE_SEND_REQUEST;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_ADD, self->comm.sfd, EPOLLOUT,
                   &self->comm.epcb);

    self->addr = strdup(addr);
    self->port = port;

    return &self->ops;
}

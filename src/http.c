#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "proxy.h"
#include "skutils.h"

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

    /* loop */
    struct loopctx *loop;
    struct epcb_ops epcb;

    /* socket */
    struct skinfo info;
    int sfd;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;

    /* target */
    char *addr;
    uint16_t port;

    /* handshake */
    int phase;
    char buffer[512];
    ssize_t nbuffer;
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
    nread = recv(self->sfd, self->buffer + self->nbuffer,
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
    nread = recv(self->sfd, self->buffer + self->nbuffer, ndiscard, 0);
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
    self->events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, self->events,
                   &self->epcb);
}

/* epoll event callback
   used of sending http request */
static void http_handshake_output(struct proxy_http *self)
{
    ssize_t nsent;

    /* it's first called to this function, assembly request */
    if (!self->nbuffer) {
        const char *lb, *rb;

        if (strchr(self->addr, ':') != NULL) {
            /* addr is IPv6 */
            lb = "[";
            rb = "]";
        } else {
            lb = rb = "";
        }

        if (strlen(current_nspconf()->proxyuser)) {
            char credentials[AUTH_MAXLEN * 2 + 1 + 1];
            char base64[BASE64_OUTLEN(AUTH_MAXLEN * 2 + 1)];

            snprintf(credentials, sizeof(credentials), "%s:%s",
                     current_nspconf()->proxyuser, current_nspconf()->proxypass);
            base64_encode(base64, sizeof(base64), credentials, 
                          strlen(credentials));

            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                "CONNECT %s%s%s:%u HTTP/1.1"       "\r\n"
                "Host: %s%s%s:%u"                  "\r\n"
                "Proxy-Authorization: Basic %s"    "\r\n"
                "\r\n",
                lb, self->addr, rb, (unsigned)self->port,
                lb, self->addr, rb, (unsigned)self->port,
                base64);
        } else {
            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                "CONNECT %s%s%s:%u HTTP/1.1"    "\r\n"
                "Host: %s%s%s:%u"               "\r\n"
                "\r\n",
                lb, self->addr, rb, (unsigned)self->port,
                lb, self->addr, rb, (unsigned)self->port);
        }
    }

    nsent = send(self->sfd, self->buffer,self->nbuffer, MSG_NOSIGNAL);
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
    loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLIN,
                   &self->epcb);
}

static void http_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct proxy_http *self = container_of(epcb, struct proxy_http, epcb);

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
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_shutdown(&self->info, self->loop, &self->sfd, how, rst);
}

/* impl for struct proxy :: evctl */
static int http_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_evctl(&self->info, self->loop, self->sfd, &self->events,
                        &self->epcb, event, enable);
}

/* impl for struct proxy :: send */
static ssize_t http_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_send(&self->info, self->sfd, data, size);
}

/* impl for struct proxy :: recv */
static ssize_t http_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_recv(&self->info, self->sfd, data, size);
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
        skutils_close_unreg(&self->info, self->loop, &self->sfd);
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

    if ((self = calloc(1, sizeof(struct proxy_http))) == NULL)
        oom();

    /* init */
    self->ops.ops = &http_ops;
    self->loop = loop;
    self->epcb.on_epoll_events = &http_epcb_events;
    self->sfd = -1;
    self->events = 0;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    /* perform connect */
    loglv(3, "http_tcp_create: connecting %s:%u/tcp", addr, (unsigned)port);

    if (strlen(addr) >= SERVNAME_MAXLEN) {
        free(self);
        return NULL;
    }

    self->sfd = skutils_connect(&self->info, conf->proxysrv, conf->proxyport,
                                SOCK_STREAM);
    if (self->sfd < 0) {
        free(self);
        return NULL;
    }

    /* good, start handshake */
    self->phase = PHASE_SEND_REQUEST;
    loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, EPOLLOUT, &self->epcb);

    self->addr = strdup(addr);
    self->port = port;

    return &self->ops;
}

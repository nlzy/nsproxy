#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
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

/* Base64 encoding table */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode function
   Returns the number of bytes written to output, or -1 on error
*/
static int base64_encode(const char *input, size_t len,
                         char *output, size_t outlen)
{
    size_t i, j;
    size_t n, k;
    unsigned char a3[3];
    unsigned char a4[4];

    if (outlen < ((len + 2) / 3) * 4 + 1)
        return -1;

    for (i = 0, j = 0; i < len;) {
        n = 0;
        for (k = 0; k < 3 && i < len; k++) {
            a3[k] = input[i++];
            n++;
        }

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) | ((n > 1 ? a3[1] : 0) >> 4);
        a4[2] = n > 1 ? (((a3[1] & 0x0f) << 2) | ((n > 2 ? a3[2] : 0) >> 6)) : 0;
        a4[3] = n > 2 ? (a3[2] & 0x3f) : 0;

        output[j++] = base64_chars[a4[0]];
        output[j++] = base64_chars[a4[1]];
        output[j++] = n > 1 ? base64_chars[a4[2]] : '=';
        output[j++] = n > 2 ? base64_chars[a4[3]] : '=';
    }

    output[j] = '\0';
    return (int)j;
}

/* Build Proxy-Authorization header with Basic auth
   Returns allocated string (must be freed by caller), or NULL on error
*/
static char *build_auth_header(const char *user, const char *pass)
{
    char credentials[192];
    char b64[256];
    char *header;
    size_t header_len;
    int cred_len, b64_len;

    cred_len = snprintf(credentials, sizeof(credentials), "%s:%s", user, pass);
    if (cred_len < 0 || (size_t)cred_len >= sizeof(credentials))
        return NULL;

    b64_len = base64_encode(credentials, cred_len, b64, sizeof(b64));
    if (b64_len < 0)
        return NULL;

    header_len = strlen("Proxy-Authorization: Basic \r\n") + b64_len + 1;
    header = malloc(header_len);
    if (!header) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    snprintf(header, header_len, "Proxy-Authorization: Basic %s\r\n", b64);
    return header;
}

struct conn_http {
    struct sk_ops ops;
    struct sk_comm comm;
    void (*userev)(void *userp, unsigned int event);
    void *userp;
    char *addr; /* for proxied connection, not proxy server */
    uint16_t port;
    int phase;
    /* for handshake only */
    char buffer[512];
    ssize_t nbuffer;
    char *auth_header; /* Proxy-Authorization header (malloc'd) */
    int refcnt;
};


/* epoll event callback
   used of receiving http response */
static void http_handshake_input(struct conn_http *self)
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
    if (nread == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        return;
    }
    if (nread == 0) {
        loglv(0, "Proxy server closed unexpectedly during HTTP handshake.");
        self->userev(self->userp, EPOLLERR);
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
            self->userev(self->userp, EPOLLERR);
        }
        /* if not failed, wait for rest handshake message */
        return;
    }

    /* check response */
    if (sscanf(self->buffer, "HTTP/1.%c %d", &vermin, &code) != 2) {
        loglv(0, "Proxy server returned invalid HTTP response header during "
                 "handshake");
        self->userev(self->userp, EPOLLERR);
        return;
    }
    if (code != 200) {
        if (code == 407 || code == 401) {
            loglv(0, "Proxy authentication failed (HTTP %d). "
                     "Please check your username and password.", code);
        } else {
            loglv(0, "Proxy server returned HTTP error %d", code);
        }
        self->userev(self->userp, EPOLLERR);
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
static void http_handshake_output(struct conn_http *self)
{
    ssize_t nsent;

    /* it's first called to this function, assembly request */
    if (!self->nbuffer) {
        if (self->auth_header) {
            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                                     "CONNECT %s:%u HTTP/1.1\r\n%s\r\n",
                                     self->addr, (unsigned int)self->port,
                                     self->auth_header);
        } else {
            self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                                     "CONNECT %s:%u HTTP/1.1\r\n\r\n",
                                     self->addr, (unsigned int)self->port);
        }
    }

    if ((nsent = send(self->comm.sfd, self->buffer, self->nbuffer, MSG_NOSIGNAL)) ==
        -1) {
        if (!is_ignored_skerr(errno)) {
            perror("send()");
            abort();
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
    struct conn_http *self = container_of(comm, struct conn_http, comm);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events);
        return;
    }

    loglv(3, "http_epcb_events: handshaking with %s:%u/tcp [%s]",
             self->addr, (unsigned)self->port, phasestr[self->phase]);

    if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN)) {
        loglv(0, "Proxy connection closed unexpectedly during HTTP handshake "
                 "phase [%s]", phasestr[self->phase]);
        self->userev(self->userp, EPOLLERR);
        return;
    }

    if (self->phase == PHASE_SEND_REQUEST) {
        http_handshake_output(self);
    } else {
        http_handshake_input(self);
    }
}

/* impl for struct sk_ops :: connect
   the argument addr and port is proxied connection, not proxy server
*/
static int http_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    struct nspconf *conf = current_nspconf();
    uint16_t proxy_port;

    loglv(3, "http_connect: connecting %s:%u/tcp", addr, (unsigned)port);

    if (strlen(addr) >= 128)
        return -1;

    /* connect to proxy server,
       save arguments addr and port, there are required in handshake */
    proxy_port = (uint16_t)atoi(conf->proxyport);
    if (skcomm_common_connect(&self->comm, conf->proxysrv, proxy_port) != 0)
        return -1;

    /* build auth header if credentials provided */
    if (conf->proxyuser[0] != '\0') {
        self->auth_header = build_auth_header(conf->proxyuser, conf->proxypass);
    }

    /* good, start handshake */
    self->phase = PHASE_SEND_REQUEST;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_ADD, self->comm.sfd, EPOLLOUT,
                   &self->comm.epcb);

    self->addr = strdup(addr);
    self->port = port;

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int http_shutdown(struct sk_ops *conn, int how, int rst)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    return skcomm_common_shutdown(&self->comm, how, rst);
}

/* impl for struct sk_ops :: evctl */
static void http_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);

    if (self->phase != PHASE_FORWARDING)
        return;

    skcomm_common_evctl(&self->comm, event, enable);
}

/* impl for struct sk_ops :: send */
static ssize_t http_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    return skcomm_common_send(&self->comm, data, size);
}

/* impl for struct sk_ops :: recv */
static ssize_t http_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    return skcomm_common_recv(&self->comm, data, size);
}

/* impl for struct sk_ops :: get */
static void http_get(struct sk_ops *conn)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    self->refcnt++;
}

/* impl for struct sk_ops :: put */
static void http_put(struct sk_ops *conn)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    if (--self->refcnt == 0) {
        skcomm_common_close(&self->comm);
        free(self->addr);
        free(self->auth_header);
        free(self);
    }
}

/* create a tcp connection
   this connection is proxied via http proxy server */
struct sk_ops *http_tcp_create(struct loopctx *loop,
                               void (*userev)(void *userp, unsigned int event),
                               void *userp)
{
    struct conn_http *self;

    loglv(3, "http_tcp_create: creating a new struct conn_http");

    if ((self = calloc(1, sizeof(struct conn_http))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    self->ops.connect = &http_connect;
    self->ops.shutdown = &http_shutdown;
    self->ops.evctl = &http_evctl;
    self->ops.send = &http_send;
    self->ops.recv = &http_recv;
    self->ops.get = &http_get;
    self->ops.put = &http_put;

    self->comm.epcb.on_epoll_events = &http_epcb_events;
    self->comm.loop = loop;
    self->comm.stype = SOCK_STREAM;
    self->comm.sfd = -1;

    return &self->ops;
}

#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

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
    struct loopctx *loop;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    char *addr; /* for proixed connection, not proxy server */
    uint16_t port;

    int sfd; /* socket fd to proxy server */
    struct ep_poller poller;

    /* for handshake only */
    /* TODO: free these buffer after handshake finished */
    char buffer[512];
    ssize_t nbuffer;

    char *auth_header; /* Proxy-Authorization header (malloc'd) */
};

/* epoll event callback used after handshake
   we don't care events after handshaked, just forward event to user */
static void http_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, poller);
    self->userev(self->userp, event);
}

/* epoll event callback
   used of receiving http response */
static void http_handshake_phase_2(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, poller);
    ssize_t nread;
    char *crlf2;
    ssize_t ndiscard;
    char vermin;
    int code;

    loglv(3, "http_handshake_phase_2: receiving response");

    if ((event & (EPOLLERR | EPOLLHUP)) && !(event & EPOLLIN)) {
        loglv(0, "Proxy connection closed unexpectedly during HTTP recieving "
                 "handshake response.");
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* Use MSG_PEEK here, if some application layer data has been returned,
       we can carefuly not to touch them
       Treat self->buffer as string, nerver forget set a '\0' after recv()
    */
    nread = recv(self->sfd, self->buffer + self->nbuffer,
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

    loglv(1, "Connected %s:%u/tcp", self->addr, (unsigned)self->port);

    /* good, handshake finish, listen and forward epoll event for user */
    loop_poller_ctl(&self->poller, EPOLL_CTL_MOD, EPOLLOUT | EPOLLIN,
                    &http_io_event);
}

/* epoll event callback
   used of sending http request */
static void http_handshake_phase_1(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, poller);
    ssize_t nsent;

    loglv(3, "http_handshake_phase_1: sending request");

    if ((event & (EPOLLERR | EPOLLHUP)) && !(event & EPOLLIN)) {
        loglv(0, "Proxy connection closed unexpectedly during HTTP sending "
                 "handshake request.");
        self->userev(self->userp, EPOLLERR);
        return;
    }

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

    if ((nsent = send(self->sfd, self->buffer, self->nbuffer, MSG_NOSIGNAL)) ==
        -1) {
        if (!is_ignored_skerr(errno)) {
            perror("send()");
            abort();
        }
        return;
    }
    self->nbuffer -= nsent;

    /* partial write, wait next time to write rest */
    if (self->nbuffer != 0) {
        memmove(self->buffer, self->buffer + nsent, self->nbuffer);
        return;
    }

    /* good, http request has been send */
    loop_poller_ctl(&self->poller, EPOLL_CTL_MOD, EPOLLIN,
                    &http_handshake_phase_2);
}

/* impl for struct sk_ops :: connect
   the argument addr and port is proxied connection, not proxy server
*/
static int http_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    struct loopconf *conf = loop_conf(self->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int const enable = 1;

    loglv(3, "http_connect: connecting %s:%u/tcp", addr, (unsigned)port);

    if (strlen(addr) >= 128)
        return -1;

    /* connect to proxy server,
       save arguments addr and port, there are required in handshake */
    if (getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result) != 0)
        return -1;

    if ((self->sfd = socket(result->ai_family,
                            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) ==
        -1) {
        perror("socket()");
        abort();
    }

    if (setsockopt(self->sfd, IPPROTO_TCP, TCP_NODELAY, &enable,
                   sizeof(enable)) == -1) {
        perror("setsockopt()");
        abort();
    }

    if (connect(self->sfd, result->ai_addr, result->ai_addrlen) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("connect()");
            abort();
        }
    }

    freeaddrinfo(result);

    /* build auth header if credentials provided */
    if (conf->proxyuser[0] != '\0') {
        self->auth_header = build_auth_header(conf->proxyuser, conf->proxypass);
    }

    /* good, start handshake */
    loop_poller_init(&self->poller, self->loop, self->sfd);
    loop_poller_ctl(&self->poller, EPOLL_CTL_ADD, EPOLLOUT,
                    &http_handshake_phase_1);

    self->addr = strdup(addr);
    self->port = port;

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int http_shutdown(struct sk_ops *conn, int how)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    int ret;

    loglv(3, "http_shutdown: shutting down %s:%u/tcp",
             self->addr, (unsigned)self->port);

    if (self->poller.on_event != &http_io_event) {
        return -ENOTCONN;
    }

    if ((ret = shutdown(self->sfd, how)) == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("shutdown()");
            abort();
        }
    }

    return ret;
}

/* impl for struct sk_ops :: evctl */
static void http_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    unsigned int new_events = self->poller.events;

    if (self->poller.on_event != &http_io_event) {
        return;
    }

    if (enable) {
        new_events |= event;
    } else {
        new_events &= ~event;
    }

    if (new_events != self->poller.events) {
        loop_poller_ctl(&self->poller, EPOLL_CTL_MOD, new_events, NULL);
    }
}

/* impl for struct sk_ops :: send */
static ssize_t http_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    ssize_t nsent;

    /* handshake is not finished */
    if (self->poller.on_event != &http_io_event) {
        return -EAGAIN;
    }

    nsent = send(self->sfd, data, size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    loglv(2, "--- http %zd bytes. %s:%u/tcp", nsent, self->addr,
          (unsigned)self->port);

    return nsent;
}

/* impl for struct sk_ops :: recv */
static ssize_t http_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    ssize_t nread;

    /* handshake is not finished */
    if (self->poller.on_event != &http_io_event) {
        return -EAGAIN;
    }

    nread = recv(self->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    loglv(2, "+++ http %zd bytes. %s:%u/tcp", nread, self->addr,
          (unsigned)self->port);

    return nread;
}

/* impl for struct sk_ops :: destory */
static void http_destroy(struct sk_ops *conn)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);

    loglv(3, "http_destroy: destroying %s:%u/tcp",
             self->addr, (unsigned)self->port);

    loop_poller_ctl(&self->poller, EPOLL_CTL_DEL, 0, NULL);

    if (shutdown(self->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    if (self->poller.on_event == &http_io_event) {
        loglv(1, "Closed %s:%u", self->addr, (unsigned)self->port);
    }

    if (close(self->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(self->addr);
    free(self->auth_header);

    free(self);
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

    self->ops.connect = &http_connect;
    self->ops.shutdown = &http_shutdown;
    self->ops.evctl = &http_evctl;
    self->ops.send = &http_send;
    self->ops.recv = &http_recv;
    self->ops.destroy = &http_destroy;

    self->loop = loop;
    self->userev = userev;
    self->userp = userp;

    return &self->ops;
}

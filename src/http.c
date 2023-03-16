#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

struct conn_http {
    struct sk_ops ops;
    struct loopctx *loop;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    char *addr; /* for proixed connection, not proxy server */
    uint16_t port;

    int sfd; /* socket fd to proxy server */
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;

    /* for handshake only */
    /* TODO: free these buffer after handshake finished */
    char buffer[512];
    ssize_t nbuffer;
};

/* epoll event callback used after handshake
   we don't care events after handshaked, just forward event to user */
void http_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, io_poller);
    self->userev(self->userp, event);
}

/* epoll event callback
   used of receiving http response */
void http_handshake_phase_2(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, io_poller);
    ssize_t nread;
    char *p; /* pointer to end of HTTP response, NULL if response not ended  */
    ssize_t s; /* how many bytes belongs HTTP response in this read */
    char vermin;
    int code;

    if (event & EPOLLERR) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* use MSG_PEEK here, if some application layer data has been returned,
       we can carefuly not to touch them
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

    p = strstr(self->buffer, "\r\n\r\n");
    s = p ? (p + strlen("\r\n\r\n") - (self->buffer + self->nbuffer)) : nread;

    /* discard http response part in socket buffer */
    if ((nread = recv(self->sfd, self->buffer + self->nbuffer, s, 0)) != s) {
        fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, s);
        abort();
    }
    self->nbuffer += nread;

    /* handshake not finished */
    if (!p) {
        /* failed, handshake not finished but connection lost or buffer full */
        if (s == 0 || self->nbuffer == sizeof(self->buffer))
            self->userev(self->userp, EPOLLERR);

        /* if not failed, wait for rest handshake message */
        return;
    }

    /* check response */
    if (sscanf(self->buffer, "HTTP/1.%c %d", &vermin, &code) != 2) {
        self->userev(self->userp, EPOLLERR);
        return;
    }
    if (code != 200) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* good, handshake finish, listen and forward epoll event for user */
    self->io_poller_ev.events = EPOLLOUT | EPOLLIN;
    self->io_poller.on_epoll_event = &http_io_event;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* epoll event callback
   used of sending http request */
void http_handshake_phase_1(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *self = container_of(poller, struct conn_http, io_poller);
    ssize_t nsent;

    if (event & EPOLLERR) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* it's first called to this function, assembly request */
    if (!self->nbuffer) {
        self->nbuffer = snprintf(self->buffer, sizeof(self->buffer),
                                 "CONNECT %s:%u HTTP/1.1\r\n\r\n", self->addr,
                                 (unsigned int)self->port);
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
    self->io_poller_ev.events = EPOLLIN;
    self->io_poller.on_epoll_event = &http_handshake_phase_2;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* impl for struct sk_ops :: connect
   the argument addr and port is proxied connection, not proxy server
*/
int http_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    struct loopconf *conf = loop_conf(self->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int const enable = 1;

    if (strlen(addr) >= 128)
        return -1;

    /* connect to proxy server,
       save arguments addr and port, there are required in handshake */
    getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result);

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

    /* good, start handshake */
    self->io_poller_ev.events = EPOLLOUT;
    self->io_poller.on_epoll_event = &http_handshake_phase_1;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_ADD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    self->addr = strdup(addr);
    self->port = port;

    return 0;
}

/* impl for struct sk_ops :: shutdown */
int http_shutdown(struct sk_ops *conn, int how)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    int ret;

    if (self->io_poller.on_epoll_event != &http_io_event) {
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
void http_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    unsigned int old = self->io_poller_ev.events;

    if (self->io_poller.on_epoll_event != &http_io_event) {
        return;
    }

    if (enable) {
        self->io_poller_ev.events |= event;
    } else {
        self->io_poller_ev.events &= ~event;
    }

    if (old != self->io_poller_ev.events) {
        if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                      &self->io_poller_ev) == -1) {
            perror("epoll_ctl()");
            abort();
        }
    }
}

/* impl for struct sk_ops :: send */
ssize_t http_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    ssize_t nsent;

    /* handshake is not finished */
    if (self->io_poller.on_epoll_event != &http_io_event) {
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

#ifndef NDEBUG
    fprintf(stderr, "--- http %zd bytes. tcp %s:%u\n", nsent, self->addr,
            (unsigned int)self->port);
#endif

    return nsent;
}

/* impl for struct sk_ops :: recv */
ssize_t http_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);
    ssize_t nread;

    /* handshake is not finished */
    if (self->io_poller.on_epoll_event != &http_io_event) {
        return -EAGAIN;
    }

    nread = recv(self->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            nread = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

#ifndef NDEBUG
    fprintf(stderr, "+++ http %zd bytes. tcp %s:%u\n", nread, self->addr,
            (unsigned int)self->port);
#endif

    return nread;
}

/* impl for struct sk_ops :: destory */
void http_destroy(struct sk_ops *conn)
{
    struct conn_http *self = container_of(conn, struct conn_http, ops);

    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_DEL, self->sfd, NULL) ==
        -1) {
        perror("epoll_ctl()");
        abort();
    }

    if (shutdown(self->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    if (close(self->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(self->addr);

    free(self);
}

/* create a tcp connection
   this connection is proxied via http proxy server */
struct sk_ops *http_tcp_create(struct loopctx *loop,
                               void (*userev)(void *userp, unsigned int event),
                               void *userp)
{
    struct conn_http *self;

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
    self->io_poller_ev.data.ptr = &self->io_poller;

    return &self->ops;
}

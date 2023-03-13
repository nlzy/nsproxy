#include "http.h"

#include <errno.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

struct conn_http {
    struct sk_ops ops;
    struct loopctx *loop;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    char *addr;
    uint16_t port;

    int sfd;
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;

    char sndbuf[512];
    ssize_t nsndbuf;

    char rcvbuf[512];
    ssize_t nrcvbuf;
};

void http_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *h = container_of(poller, struct conn_http, io_poller);
    h->userev(h->userp, event);
}

void http_handshake_phase_2(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *h = container_of(poller, struct conn_http, io_poller);
    ssize_t nread;
    char *p;
    ssize_t s;
    char vermin;
    int code;

    if (event & EPOLLERR) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if ((nread = recv(h->sfd, h->rcvbuf + h->nrcvbuf,
                      sizeof(h->rcvbuf) - h->nrcvbuf - 1, MSG_PEEK)) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        return;
    }

    p = strstr(h->rcvbuf, "\r\n\r\n");
    s = p ? (p + strlen("\r\n\r\n") - (h->rcvbuf + h->nrcvbuf)) : nread;

    if ((nread = recv(h->sfd, h->rcvbuf + h->nrcvbuf, s, 0)) != s) {
        if (nread == -1 && !is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        h->userev(h->userp, EPOLLERR);
        return;
    }
    h->nrcvbuf += nread;

    if (!p) {
        if (h->nrcvbuf == sizeof(h->rcvbuf) || nread == 0)
            h->userev(h->userp, EPOLLERR);
        return;
    }

    if (sscanf(h->rcvbuf, "HTTP/1.%c %d", &vermin, &code) != 2) {
        h->userev(h->userp, EPOLLERR);
        return;
    }
    if (code != 200) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    h->io_poller_ev.events = EPOLLOUT | EPOLLIN;
    h->io_poller.on_epoll_event = &http_io_event;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void http_handshake_phase_1(struct ep_poller *poller, unsigned int event)
{
    struct conn_http *h = container_of(poller, struct conn_http, io_poller);
    ssize_t nsent;

    if (event & EPOLLERR) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (!h->nsndbuf) {
        h->nsndbuf = snprintf(h->sndbuf, sizeof(h->sndbuf),
                              "CONNECT %s:%u HTTP/1.1\r\n\r\n", h->addr,
                              (unsigned int)h->port);
    }

    if ((nsent = send(h->sfd, h->sndbuf, h->nsndbuf, MSG_NOSIGNAL)) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("send()");
            abort();
        }
        return;
    }
    h->nsndbuf -= nsent;

    if (h->nsndbuf != 0) {
        memmove(h->sndbuf, h->sndbuf + nsent, h->nsndbuf);
        return;
    }

    h->io_poller_ev.events = EPOLLIN;
    h->io_poller.on_epoll_event = &http_handshake_phase_2;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

int http_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_http *h = (struct conn_http *)handle;
    struct loopconf *conf = loop_conf(h->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;

    getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result);

    if ((h->sfd = socket(result->ai_family,
                         SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) ==
        -1) {
        perror("socket()");
        abort();
    }

    if (connect(h->sfd, result->ai_addr, result->ai_addrlen) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("connect()");
            abort();
        }
    }

    freeaddrinfo(result);

    h->io_poller_ev.events = EPOLLOUT;
    h->io_poller.on_epoll_event = &http_handshake_phase_1;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_ADD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    h->addr = strdup(addr);
    h->port = port;

    return 0;
}

int http_shutdown(struct sk_ops *handle, int how)
{
    struct conn_http *h = (struct conn_http *)handle;
    int ret;

    if (h->io_poller.on_epoll_event != &http_io_event) {
        return -ENOTCONN;
    }

    if ((ret = shutdown(h->sfd, how)) == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("shutdown()");
            abort();
        }
    }

    return ret;
}

void http_evctl(struct sk_ops *handle, unsigned int event, int enable)
{
    struct conn_http *h = (struct conn_http *)handle;
    unsigned int old = h->io_poller_ev.events;

    if (h->io_poller.on_epoll_event != &http_io_event) {
        return;
    }

    if (enable) {
        h->io_poller_ev.events |= event;
    } else {
        h->io_poller_ev.events &= ~event;
    }

    if (old != h->io_poller_ev.events) {
        if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                      &h->io_poller_ev) == -1) {
            perror("epoll_ctl()");
            abort();
        }
    }
}

ssize_t http_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_http *h = (struct conn_http *)handle;
    ssize_t nsent;

    if (h->io_poller.on_epoll_event != &http_io_event) {
        return -EAGAIN;
    }

    nsent = send(h->sfd, data, size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

#ifndef NDEBUG
    fprintf(stderr, "--- http %zd bytes. tcp %s:%u\n", nsent, h->addr,
            (unsigned int)h->port);
#endif

    return nsent;
}

ssize_t http_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_http *h = (struct conn_http *)handle;
    ssize_t nread;

    if (h->io_poller.on_epoll_event != &http_io_event) {
        return -EAGAIN;
    }

    nread = recv(h->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            nread = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

#ifndef NDEBUG
    fprintf(stderr, "+++ http %zd bytes. tcp %s:%u\n", nread, h->addr,
            (unsigned int)h->port);
#endif

    return nread;
}

void http_destroy(struct sk_ops *handle)
{
    struct conn_http *h = (struct conn_http *)handle;

    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_DEL, h->sfd, NULL) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    if (shutdown(h->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    if (close(h->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(h->addr);

    free(h);
}

int http_tcp_create(struct sk_ops **handle, struct loopctx *loop,
                    void (*userev)(void *userp, unsigned int event),
                    void *userp)
{
    struct conn_http *h;

    if ((h = calloc(1, sizeof(struct conn_http))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    h->ops.connect = &http_connect;
    h->ops.shutdown = &http_shutdown;
    h->ops.evctl = &http_evctl;
    h->ops.send = &http_send;
    h->ops.recv = &http_recv;
    h->ops.destroy = &http_destroy;

    h->loop = loop;
    h->userev = userev;
    h->userp = userp;
    h->io_poller_ev.data.ptr = &h->io_poller;

    *handle = &h->ops;
    return 0;
}

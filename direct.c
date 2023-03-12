#include "direct.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

struct conn_direct {
    struct sk_ops ops;
    struct context_loop *ctx;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    int isudp;
    char *addr;
    uint16_t port;

    int sfd;
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;
};

void direct_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_direct *h = container_of(poller, struct conn_direct, io_poller);
    h->userev(h->userp, event);
}

int direct_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    char strport[8];
    int sktype = h->isudp ? SOCK_DGRAM : SOCK_STREAM;

    snprintf(strport, sizeof(strport), "%u", (unsigned int)port);

    getaddrinfo(addr, strport, &hints, &result);

    if ((h->sfd = socket(result->ai_family,
                         sktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
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

    h->io_poller.on_epoll_event = &direct_io_event;
    h->io_poller_ev.events = EPOLLIN | EPOLLOUT;
    h->io_poller_ev.data.ptr = &h->io_poller;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_ADD, h->sfd, &h->io_poller_ev) ==
        -1) {
        perror("epoll_ctl()");
        abort();
    }

    h->addr = strdup(addr);
    h->port = port;

    return 0;
}

int direct_shutdown(struct sk_ops *handle, int how)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    int ret;

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

void direct_evctl(struct sk_ops *handle, unsigned int event, int enable)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    unsigned int old = h->io_poller_ev.events;

    if (enable) {
        h->io_poller_ev.events |= event;
    } else {
        h->io_poller_ev.events &= ~event;
    }

    if (old != h->io_poller_ev.events) {
        if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd,
                      &h->io_poller_ev) == -1) {
            perror("epoll_ctl()");
            abort();
        }
    }
}

ssize_t direct_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    ssize_t nsent;

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
    fprintf(stderr, "--- direct %zd bytes. %s %s:%u\n", nsent,
            h->isudp ? "UDP" : "TCP", h->addr, (unsigned int)h->port);
#endif

    return nsent;
}

ssize_t direct_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    ssize_t nread;

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
    fprintf(stderr, "+++ direct %zd bytes. %s %s:%u\n", nread,
            h->isudp ? "UDP" : "TCP", h->addr, (unsigned int)h->port);
#endif

    return nread;
}

void direct_destroy(struct sk_ops *handle)
{
    struct conn_direct *h = (struct conn_direct *)handle;

    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_DEL, h->sfd, NULL) == -1) {
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

struct conn_direct *direct_create_internel()
{
    struct conn_direct *h;

    if ((h = malloc(sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    h->ops.connect = &direct_connect;
    h->ops.shutdown = &direct_shutdown;
    h->ops.evctl = &direct_evctl;
    h->ops.send = &direct_send;
    h->ops.recv = &direct_recv;
    h->ops.destroy = &direct_destroy;

    return h;
}

int direct_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void (*userev)(void *userp, unsigned int event),
                      void *userp)
{
    struct conn_direct *h = direct_create_internel();

    h->isudp = 0;
    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

int direct_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void (*userev)(void *userp, unsigned int event),
                      void *userp)
{
    struct conn_direct *h = direct_create_internel();

    h->isudp = 1;
    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

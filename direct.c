#include "direct.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

struct conn_direct {
    struct sk_ops ops;
    struct ep_poller io_poller;
    struct context_loop *ctx;
    void (*userev)(void *userp, int event);
    void *userp;
    struct epoll_event ev;
    char desc[32];
    int sfd;
};

static void enable_event(struct conn_direct *h, int ev)
{
    h->ev.events |= ev;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

static void disable_event(struct conn_direct *h, int ev)
{
    h->ev.events &= ~ev;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

int direct_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    struct sockaddr_in sa4 = { .sin_family = AF_INET,
                               .sin_port = htobe16(port) };

    if (inet_pton(AF_INET, addr, &sa4.sin_addr) == 0) {
        fprintf(stderr, "direct_connect: invaild argument: addr\n");
        abort();
    }

    if (connect(h->sfd, (struct sockaddr *)&sa4, sizeof(sa4)) == -1) {
        if (errno != EINPROGRESS) {
            perror("connect()");
            abort();
        }
    }

    h->ev.events = EPOLLIN | EPOLLOUT;
    h->ev.data.ptr = &h->io_poller;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_ADD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    return 0;
}

int direct_shutdown(struct sk_ops *handle, int how)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    int ret;

    if ((ret = shutdown(h->sfd, how)) == -1) {
        if (errno == ENOTCONN) {
            return -errno;
        } else {
            perror("shutdown()");
            abort();
        }
    }

    return ret;
}

ssize_t direct_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    ssize_t nsent;

    if (size == 0) {
        /* no data to send, stop report LOOP_EVENT_WR */
        disable_event(h, EPOLLOUT);
        return -EAGAIN;
    }

    nsent = send(h->sfd, data, size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno == EAGAIN) {
            enable_event(h, EPOLLOUT);
            nsent = -errno;
        } else if (errno == ECONNRESET || errno == ECONNREFUSED ||
                   errno == EPIPE || errno == ETIMEDOUT) {
            disable_event(h, EPOLLOUT);
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

#ifndef NDEBUG
    fprintf(stderr, "--- direct %s %zd bytes.\n", h->desc, nsent);
#endif

    return nsent;
}

ssize_t direct_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_direct *h = (struct conn_direct *)handle;
    ssize_t nread;

    if (size == 0) {
        /* no buffer to recv, stop report LOOP_EVENT_RD */
        disable_event(h, EPOLLIN);
        return -EAGAIN;
    }

    nread = recv(h->sfd, data, size, 0);
    if (nread == -1) {
        if (errno == EAGAIN) {
            enable_event(h, EPOLLIN);
            nread = -errno;
        } else if (errno == ECONNRESET || errno == ECONNREFUSED ||
                   errno == EPIPE || errno == ETIMEDOUT) {
            disable_event(h, EPOLLIN);
            nread = -errno;
        } else {
            perror("recv()");
            abort();
        }
    } else if (nread == 0) {
        disable_event(h, EPOLLIN);
    } /* - else return nread */

#ifndef NDEBUG
    fprintf(stderr, "+++ direct %s %zd bytes.\n", h->desc, nread);
#endif

    return nread;
}

void direct_io_event(struct ep_poller *poller, int event)
{
    struct conn_direct *h = container_of(poller, struct conn_direct, io_poller);

    h->userev(h->userp, event);
}

void direct_destroy(struct sk_ops *handle)
{
    struct conn_direct *h = (struct conn_direct *)handle;

    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_DEL, h->sfd, NULL) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    if (shutdown(h->sfd, SHUT_RDWR) == -1) {
        if (errno != ENOTCONN) {
            perror("shutdown()");
            abort();
        }
    }

    if (close(h->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(h);
}

int direct_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, int event))
{
    struct conn_direct *h;

    if ((h = malloc(sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    if ((h->sfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_TCP)) == -1) {
        perror("socket()");
        abort();
    }

    snprintf(h->desc, sizeof(h->desc), "TCP");

    h->ops.connect = &direct_connect;
    h->ops.shutdown = &direct_shutdown;
    h->ops.send = &direct_send;
    h->ops.recv = &direct_recv;
    h->ops.destroy = &direct_destroy;

    h->io_poller.on_epoll_event = &direct_io_event;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

int direct_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, int event))
{
    struct conn_direct *h;

    if ((h = malloc(sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    if ((h->sfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_UDP)) == -1) {
        perror("socket()");
        abort();
    }

    snprintf(h->desc, sizeof(h->desc), "UDP");

    h->ops.connect = &direct_connect;
    h->ops.shutdown = &direct_shutdown;
    h->ops.send = &direct_send;
    h->ops.recv = &direct_recv;
    h->ops.destroy = &direct_destroy;

    h->io_poller.on_epoll_event = &direct_io_event;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

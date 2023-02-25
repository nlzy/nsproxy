#include "socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

enum {
    SOCKSS_SEND_METHODS,
    SOCKSS_RECV_METHOD,
    SOCKSS_SEND_REQUEST,
    SOCKSS_RECV_REPLIES,
    SOCKSS_FORWARD
};

struct conn_socks {
    struct sk_ops ops;
    struct ep_poller io_poller;
    struct context_loop *ctx;
    void (*userev)(void *userp, int event);
    void *userp;
    struct epoll_event ev;

    char *addr;
    uint16_t port;

    int isudp;

    char desc[32];

    char snd_buffer[512];
    size_t snd_buffer_size;

    char rcv_buffer[512];
    size_t rcv_buffer_size;

    int sfd;
};

struct socks5hdr {
    uint8_t ver;
    uint8_t cr;
    uint8_t rsv;
    uint8_t atyp;
};

void socks_handshake_send_methods(struct ep_poller *poller, int event);
void socks_handshake_recv_methods(struct ep_poller *poller, int event);
void socks_handshake_send_request(struct ep_poller *poller, int event);
void socks_handshake_recv_replies(struct ep_poller *poller, int event);

static void enable_event(struct conn_socks *h, int ev)
{
    h->ev.events |= ev;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

static void disable_event(struct conn_socks *h, int ev)
{
    h->ev.events &= ~ev;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_io_event(struct ep_poller *poller, int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);

    h->userev(h->userp, event);
}

int socks_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    struct sockaddr_in sa = { .sin_family = AF_INET };

    /* FIXME: make configurable */
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    sa.sin_port = htobe16(1081);

    if (connect(h->sfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        if (errno != EINPROGRESS) {
            perror("connect()");
            abort();
        }
    }

    if (h->isudp) {
        h->io_poller.on_epoll_event = &socks_io_event;
        h->ev.events = EPOLLOUT | EPOLLIN;
    } else {
        h->io_poller.on_epoll_event = &socks_handshake_send_methods;
        h->ev.events = EPOLLOUT;
    }

    h->ev.data.ptr = &h->io_poller;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_ADD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    h->addr = strdup(addr);
    h->port = port;

    return 0;
}

int socks_shutdown(struct sk_ops *handle, int how)
{
    struct conn_socks *h = (struct conn_socks *)handle;
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

ssize_t socks_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    char buffer[65535];
    ssize_t nsent;
    const char *p;
    size_t s;
    struct socks5hdr hdr = { 0 };
    struct sockaddr_in sa;

    if (size == 0) {
        /* no data to send, stop report LOOP_EVENT_WR */
        disable_event(h, EPOLLOUT);
        return -EAGAIN;
    }

    if (h->isudp) {
        if (size + 10 > sizeof(buffer)) {
            return -EAGAIN; /* TODO: return TRUNC errno */
        }

        hdr.atyp = 1;
        memcpy(buffer, &hdr, sizeof(hdr));

        inet_pton(AF_INET, h->addr, &sa.sin_addr);
        sa.sin_port = htobe16(h->port);
        memcpy(buffer + 4, &sa.sin_addr, sizeof(sa.sin_addr));
        memcpy(buffer + 8, &sa.sin_port, sizeof(sa.sin_port));

        memcpy(buffer + 10, data, size);

        p = buffer;
        s = size + 10;
    } else {
        p = data;
        s = size;
    }

    nsent = send(h->sfd, p, s, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno == EAGAIN) {
            enable_event(h, EPOLLOUT);
            nsent = -errno;
        } else if (errno == ECONNRESET || errno == ECONNREFUSED ||
                   errno == EPIPE) {
            disable_event(h, EPOLLOUT);
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    fprintf(stderr, "--- socks %s %zd bytes.\n", h->desc, nsent);

    return nsent;
}

ssize_t socks_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_socks *h = (struct conn_socks *)handle;
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
                   errno == EPIPE) {
            disable_event(h, EPOLLIN);
            nread = -errno;
        } else {
            perror("recv()");
            abort();
        }
    } else if (nread == 0) {
        disable_event(h, EPOLLIN);
    } /* - else return nread */

    fprintf(stderr, "+++ socks %s %zd bytes.\n", h->desc, nread);

    if (h->isudp) {
        if (size < 10) {
            return -EAGAIN; /* bad */
        }
        memmove(data, data + 10, size - 10);
        nread -= 10;
    }

    return nread;
}

void socks_destroy(struct sk_ops *handle)
{
    struct conn_socks *h = (struct conn_socks *)handle;

    epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_DEL, h->sfd, NULL);
    shutdown(h->sfd, SHUT_RDWR);
    close(h->sfd);
    free(h->addr);
    free(h);
}

void socks_handshake_send_methods(struct ep_poller *poller, int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    char methods[] = { 5, 1, 0 };
    ssize_t nsent;

    /* TODO: socks5 password auth */
    if ((nsent = send(h->sfd, &methods, sizeof(methods), MSG_NOSIGNAL)) == -1) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (nsent != sizeof(methods)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    enable_event(h, EPOLLIN);
    disable_event(h, EPOLLOUT);
    h->io_poller.on_epoll_event = &socks_handshake_recv_methods;
}

void socks_handshake_recv_methods(struct ep_poller *poller, int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    char methods[64];
    ssize_t nread;

    if ((nread = recv(h->sfd, &methods, sizeof(methods), 0)) == -1) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (nread < 2) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (methods[0] != 5 && methods[1] != 0) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    enable_event(h, EPOLLOUT);
    disable_event(h, EPOLLIN);
    h->io_poller.on_epoll_event = &socks_handshake_send_request;
}

void socks_handshake_send_request(struct ep_poller *poller, int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    char request[] = { 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 };
    ssize_t nsent;

    inet_pton(AF_INET, h->addr, request + 4);
    request[8] = h->port >> 8 & 0xFF;
    request[9] = h->port & 0xFF;

    if ((nsent = send(h->sfd, &request, sizeof(request), MSG_NOSIGNAL)) == -1) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (nsent != sizeof(request)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    enable_event(h, EPOLLIN);
    disable_event(h, EPOLLOUT);
    h->io_poller.on_epoll_event = &socks_handshake_recv_replies;
}

void socks_handshake_recv_replies(struct ep_poller *poller, int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    char methods[64];
    ssize_t nread;

    if ((nread = recv(h->sfd, &methods, sizeof(methods), 0)) == -1) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (nread < 10) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (methods[0] != 5 && methods[1] != 0) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    enable_event(h, EPOLLOUT);
    enable_event(h, EPOLLIN);
    h->io_poller.on_epoll_event = &socks_io_event;
}

int socks_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void *userp, void (*userev)(void *userp, int event))
{
    struct conn_socks *h;

    if ((h = calloc(1, sizeof(struct conn_socks))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    if ((h->sfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_TCP)) == -1) {
        perror("socket()");
        abort();
    }

    snprintf(h->desc, sizeof(h->desc), "TCP");

    h->ops.connect = &socks_connect;
    h->ops.shutdown = &socks_shutdown;
    h->ops.send = &socks_send;
    h->ops.recv = &socks_recv;
    h->ops.destroy = &socks_destroy;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

int socks_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void *userp, void (*userev)(void *userp, int event))
{
    struct conn_socks *h;

    if ((h = calloc(1, sizeof(struct conn_socks))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    if ((h->sfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_UDP)) == -1) {
        perror("socket()");
        abort();
    }

    snprintf(h->desc, sizeof(h->desc), "UDP");

    h->ops.connect = &socks_connect;
    h->ops.shutdown = &socks_shutdown;
    h->ops.send = &socks_send;
    h->ops.recv = &socks_recv;
    h->ops.destroy = &socks_destroy;

    h->isudp = 1;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

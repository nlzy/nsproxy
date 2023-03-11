#include "socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

struct conn_socks {
    struct sk_ops ops;
    struct ep_poller io_poller;
    struct context_loop *ctx;
    void (*userev)(void *userp, unsigned int event);
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

void socks_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    h->userev(h->userp, event);
}

void socks_handshake_phase_4(struct ep_poller *poller, unsigned int event)
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

    h->ev.events = EPOLLIN | EPOLLOUT;
    h->io_poller.on_epoll_event = &socks_io_event;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_3(struct ep_poller *poller, unsigned int event)
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

    h->ev.events = EPOLLIN;
    h->io_poller.on_epoll_event = &socks_handshake_phase_4;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_2(struct ep_poller *poller, unsigned int event)
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

    h->ev.events = EPOLLOUT;
    h->io_poller.on_epoll_event = &socks_handshake_phase_3;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_1(struct ep_poller *poller, unsigned int event)
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

    h->ev.events = EPOLLIN;
    h->io_poller.on_epoll_event = &socks_handshake_phase_2;
    if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

int socks_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int sktype = h->isudp ? SOCK_DGRAM : SOCK_STREAM;

    /* FIXME: make configurable */
    /* FIXME: make non block */
    getaddrinfo(CONFIG_SOCK_ADDR, CONFIG_SOCK_PORT, &hints, &result);

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

    if (h->isudp) {
        h->io_poller.on_epoll_event = &socks_io_event;
        h->ev.events = EPOLLOUT | EPOLLIN;
    } else {
        h->io_poller.on_epoll_event = &socks_handshake_phase_1;
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

    if (h->io_poller.on_epoll_event != &socks_io_event) {
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

void socks_evctl(struct sk_ops *handle, unsigned int event, int enable)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    unsigned int old = h->ev.events;

    if (h->io_poller.on_epoll_event != &socks_io_event) {
        return;
    }

    if (enable) {
        h->ev.events |= event;
    } else {
        h->ev.events &= ~event;
    }

    if (old != h->ev.events) {
        if (epoll_ctl(loop_epfd(h->ctx), EPOLL_CTL_MOD, h->sfd, &h->ev) == -1) {
            perror("epoll_ctl()");
            abort();
        }
    }
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

    if (h->io_poller.on_epoll_event != &socks_io_event) {
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
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

#ifndef NDEBUG
    fprintf(stderr, "--- socks %s %zd bytes.\n", h->desc, nsent);
#endif

    return nsent;
}

ssize_t socks_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    ssize_t nread;

    if (h->io_poller.on_epoll_event != &socks_io_event) {
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
    fprintf(stderr, "+++ socks %s %zd bytes.\n", h->desc, nread);
#endif

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

struct conn_socks *socks_create_internal()
{
    struct conn_socks *h;

    if ((h = calloc(1, sizeof(struct conn_socks))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    h->ops.connect = &socks_connect;
    h->ops.shutdown = &socks_shutdown;
    h->ops.evctl = &socks_evctl;
    h->ops.send = &socks_send;
    h->ops.recv = &socks_recv;
    h->ops.destroy = &socks_destroy;

    return h;
}

int socks_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp)
{
    struct conn_socks *h = socks_create_internal();

    snprintf(h->desc, sizeof(h->desc), "TCP");
    h->isudp = 0;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

int socks_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp)
{
    struct conn_socks *h = socks_create_internal();

    snprintf(h->desc, sizeof(h->desc), "UDP");
    h->isudp = 1;

    h->ctx = ctx;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

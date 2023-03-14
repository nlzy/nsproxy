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
    struct loopctx *loop;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    int isudp;
    char *addr;
    uint16_t port;

    int sfd;
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;

    char sndbuf[512];
    size_t nsndbuf;

    char rcvbuf[512];
    size_t nrcvbuf;
};

struct socks5hdr {
    uint8_t ver;
    union {
        uint8_t cmd;
        uint8_t rsp;
    };
    union {
        uint8_t rsv;
        uint8_t frag;
    };
};

struct socks5addr {
    char addr[256];
    uint16_t port;
};
#define SOCKS5_ATYPE_INET4  1
#define SOCKS5_ATYPE_DOMAIN 3
#define SOCKS5_ATYPE_INET6  4

#define SOCKS5_CMD_CONNECT  1
#define SOCKS5_CMD_UDPASSOC 3

static ssize_t socks5_hdr_put(char *buffer, size_t size,
                              const struct socks5hdr *hdr)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(buffer, hdr, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

static ssize_t socks5_hdr_get(struct socks5hdr *hdr, const char *buffer,
                              size_t size)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(hdr, buffer, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

static ssize_t socks5_addr_put(char *buffer, size_t size,
                               const struct socks5addr *ad)
{
    size_t offset = 0;
    struct in_addr in4;
    struct in6_addr in6;
    uint8_t atype, alen;
    const void *aptr;
    uint16_t portbe = htobe16(ad->port);

    if (inet_pton(AF_INET, ad->addr, &in4) == 1) {
        atype = SOCKS5_ATYPE_INET4;
        alen = sizeof(in4);
        aptr = &in4;
    } else if (inet_pton(AF_INET6, ad->addr, &in6) == 1) {
        atype = SOCKS5_ATYPE_INET6;
        alen = sizeof(in6);
        aptr = &in6;
    } else {
        atype = SOCKS5_ATYPE_DOMAIN;
        alen = strlen(ad->addr);
        aptr = ad->addr;
    }

    if (atype == SOCKS5_ATYPE_DOMAIN) {
        if (sizeof(atype) + sizeof(alen) + alen + sizeof(portbe) > size)
            return -1;
    } else {
        if (sizeof(atype) + alen + sizeof(portbe) > size)
            return -1;
    }

    memcpy(buffer + offset, &atype, sizeof(atype));
    offset += sizeof(atype);

    if (atype == SOCKS5_ATYPE_DOMAIN) {
        memcpy(buffer + offset, &alen, sizeof(alen));
        offset += sizeof(alen);
    }

    memcpy(buffer + offset, aptr, alen);
    offset += alen;

    memcpy(buffer + offset, &portbe, sizeof(portbe));
    offset += sizeof(portbe);

    return offset;
}

static ssize_t socks5_addr_get(struct socks5addr *ad, const char *buffer,
                               size_t size)
{
    const char *cur = buffer;
    struct in_addr in4;
    struct in6_addr in6;
    uint8_t atype, alen;
    uint16_t portbe;

    if (cur - buffer + sizeof(atype) > size)
        return -1;
    memcpy(&atype, cur, sizeof(atype));
    cur += sizeof(atype);

    switch (atype) {
    case SOCKS5_ATYPE_INET4:
        if (cur - buffer + sizeof(in4) > size)
            return -1;
        memcpy(&in4, cur, sizeof(in4));
        cur += sizeof(in4);

        inet_ntop(AF_INET, &in4, ad->addr, sizeof(ad->addr));
        break;

    case SOCKS5_ATYPE_INET6:
        if (cur - buffer + sizeof(in6) > size)
            return -1;
        memcpy(&in6, cur, sizeof(in6));
        cur += sizeof(in6);

        inet_ntop(AF_INET6, &in6, ad->addr, sizeof(ad->addr));
        break;

    case SOCKS5_ATYPE_DOMAIN:
        if (cur - buffer + sizeof(alen) > size)
            return -1;
        memcpy(&alen, cur, sizeof(alen));
        cur += sizeof(alen);

        if (cur - buffer + alen > (ssize_t)size)
            return -1;
        memset(ad->addr, 0, sizeof(ad->addr));
        memcpy(ad->addr, cur, alen);
        cur += alen;
        break;

    default:
        return -1;
    }

    if (cur - buffer + sizeof(portbe) > size)
        return -1;
    memcpy(&portbe, cur, sizeof(portbe));
    cur += sizeof(portbe);

    ad->port = be16toh(portbe);

    return cur - buffer;
}

void socks_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    h->userev(h->userp, event);
}

void socks_handshake_phase_4(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    struct socks5hdr hdr;
    struct socks5addr ad;
    ssize_t s, nread;
    int pass;

    if (event & (EPOLLERR | EPOLLHUP)) {
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

    do {
        ssize_t ret, offset = 0;

        s = nread;
        pass = 0;

        ret = socks5_hdr_get(&hdr, h->rcvbuf + offset,
                             h->nrcvbuf + nread - offset);
        if (ret == -1)
            break;
        offset += ret;

        ret = socks5_addr_get(&ad, h->rcvbuf + offset,
                              h->nrcvbuf + nread - offset);
        if (ret == -1)
            break;
        offset += ret;

        s = offset - h->nrcvbuf;
        pass = 1;
    } while (0);

    if ((nread = recv(h->sfd, h->rcvbuf + h->nrcvbuf, s, 0)) != s) {
        fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, s);
        abort();
    }
    h->nrcvbuf += nread;

    if (h->nrcvbuf == sizeof(h->rcvbuf)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (!pass) {
        if (s == 0)
            h->userev(h->userp, EPOLLERR);
        return;
    }

    if (hdr.ver != 5 || hdr.rsp != 0) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    h->io_poller_ev.events = EPOLLIN | EPOLLOUT;
    h->io_poller.on_epoll_event = &socks_io_event;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_3(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    ssize_t nsent;

    if (event & (EPOLLERR | EPOLLHUP)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (h->nsndbuf == 0) {
        struct socks5hdr hdr = { .ver = 5, .cmd = SOCKS5_CMD_CONNECT };
        struct socks5addr ad;
        ssize_t ret;

        strncpy(ad.addr, h->addr, sizeof(ad.addr) - 1);
        ad.port = h->port;

        ret = socks5_hdr_put(h->sndbuf + h->nsndbuf,
                             sizeof(h->sndbuf) - h->nsndbuf, &hdr);
        if (ret == -1) {
            h->userev(h->userp, EPOLLERR);
            return;
        }
        h->nsndbuf += ret;

        ret = socks5_addr_put(h->sndbuf + h->nsndbuf,
                              sizeof(h->sndbuf) - h->nsndbuf, &ad);
        if (ret == -1) {
            h->userev(h->userp, EPOLLERR);
            return;
        }
        h->nsndbuf += ret;
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
    h->io_poller.on_epoll_event = &socks_handshake_phase_4;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_2(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    ssize_t nread;

    if (event & (EPOLLERR | EPOLLHUP)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if ((nread = recv(h->sfd, h->rcvbuf + h->nrcvbuf,
                      sizeof(h->rcvbuf) - h->nrcvbuf, 0)) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        return;
    }
    h->nrcvbuf += nread;

    if (h->nrcvbuf == 0 || h->nrcvbuf > 2) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (h->nrcvbuf == 1)
        return;

    if (h->rcvbuf[0] != 5 || h->rcvbuf[1] != 0) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    h->nrcvbuf = 0;
    h->io_poller_ev.events = EPOLLOUT;
    h->io_poller.on_epoll_event = &socks_handshake_phase_3;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

void socks_handshake_phase_1(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *h = container_of(poller, struct conn_socks, io_poller);
    ssize_t nsent;

    if (event & (EPOLLERR | EPOLLHUP)) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (h->nsndbuf == 0) {
        if (sizeof(h->sndbuf) < 3) {
            h->userev(h->userp, EPOLLERR);
            return;
        }
        h->sndbuf[h->nsndbuf++] = 5; /* ver */
        h->sndbuf[h->nsndbuf++] = 1; /* num */
        h->sndbuf[h->nsndbuf++] = 0; /* no auth */
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
    h->io_poller.on_epoll_event = &socks_handshake_phase_2;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_MOD, h->sfd,
                  &h->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

int socks_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    struct loopconf *conf = loop_conf(h->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int sktype = h->isudp ? SOCK_DGRAM : SOCK_STREAM;

    getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result);

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
        h->io_poller_ev.events = EPOLLOUT | EPOLLIN;
    } else {
        h->io_poller.on_epoll_event = &socks_handshake_phase_1;
        h->io_poller_ev.events = EPOLLOUT;
    }

    h->io_poller_ev.data.ptr = &h->io_poller;
    if (epoll_ctl(loop_epfd(h->loop), EPOLL_CTL_ADD, h->sfd,
                  &h->io_poller_ev) == -1) {
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
    unsigned int old = h->io_poller_ev.events;

    if (h->io_poller.on_epoll_event != &socks_io_event) {
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

ssize_t socks_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_socks *h = (struct conn_socks *)handle;
    ssize_t nsent;

    if (h->io_poller.on_epoll_event != &socks_io_event) {
        return -EAGAIN;
    }

    if (h->isudp) {
        char buffer[512];
        struct socks5hdr hdr = { 0 };
        struct socks5addr addr;
        size_t offset = 0;
        ssize_t ret;

        strncpy(addr.addr, h->addr, sizeof(addr.addr) - 1);
        addr.port = h->port;

        if ((ret = socks5_hdr_put(buffer + offset, sizeof(buffer) - offset,
                                  &hdr)) == -1)
            return -EAGAIN;
        offset += ret;

        if ((ret = socks5_addr_put(buffer + offset, sizeof(buffer) - offset,
                                   &addr)) == -1)
            return -EAGAIN;
        offset += ret;

        if (offset + size > 65535 - 8 - 40)
            return -EAGAIN;

        nsent = send(h->sfd, buffer, offset, MSG_NOSIGNAL | MSG_MORE);
        if (nsent == -1) {
            if (is_ignored_skerr(errno)) {
                nsent = -errno;
            } else {
                perror("send()");
                abort();
            }
        }
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
    fprintf(stderr, "--- socks %zd bytes. %s %s:%u\n", nsent,
            h->isudp ? "UDP" : "TCP", h->addr, (unsigned int)h->port);
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
    fprintf(stderr, "+++ socks %zd bytes. %s %s:%u\n", nread,
            h->isudp ? "UDP" : "TCP", h->addr, (unsigned int)h->port);
#endif

    if (h->isudp) {
        struct socks5hdr hdr;
        struct socks5addr ad;
        ssize_t ret, offset = 0;

        ret = socks5_hdr_get(&hdr, data + offset, nread - offset);
        if (ret == -1)
            return -EAGAIN;
        offset += ret;

        ret = socks5_addr_get(&ad, data + offset, nread - offset);
        if (ret == -1)
            return -EAGAIN;
        offset += ret;

        memmove(data, data + offset, nread - offset);
        nread -= offset;
    }

    return nread;
}

void socks_destroy(struct sk_ops *handle)
{
    struct conn_socks *h = (struct conn_socks *)handle;

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

int socks_tcp_create(struct sk_ops **handle, struct loopctx *loop,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp)
{
    struct conn_socks *h = socks_create_internal();

    h->isudp = 0;
    h->loop = loop;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

int socks_udp_create(struct sk_ops **handle, struct loopctx *loop,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp)
{
    struct conn_socks *h = socks_create_internal();

    h->isudp = 1;
    h->loop = loop;
    h->userev = userev;
    h->userp = userp;
    *handle = &h->ops;
    return 0;
}

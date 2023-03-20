#include "socks.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
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
    char *addr; /* for proixed connection, not proxy server */
    uint16_t port;

    int sfd; /* socket fd to proxy server */
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;

    /* for handshake only */
    /* TODO: free these buffer after handshake finished */
    char buffer[512];
    size_t nbuffer;
};

struct socks5hdr {
    uint8_t ver;
    union {
        uint8_t cmd; /* for request */
        uint8_t rsp; /* for reply */
    };
    union {
        uint8_t rsv;
        uint8_t frag /* for udp only */;
    };
};

/* not really message layout, just used as parameter type for util function */
struct socks5addr {
    char addr[256];
    uint16_t port;
};
#define SOCKS5_ATYPE_INET4  1
#define SOCKS5_ATYPE_DOMAIN 3
#define SOCKS5_ATYPE_INET6  4

#define SOCKS5_CMD_CONNECT  1
#define SOCKS5_CMD_UDPASSOC 3

/* put socks5 header to buffer,
   return the number of bytes written , or -1 if failed */
static ssize_t socks5_hdr_put(char *buffer, size_t size,
                              const struct socks5hdr *hdr)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(buffer, hdr, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

/* get socks5 header from buffer,
   return the number of bytes written, or -1 if failed */
static ssize_t socks5_hdr_get(struct socks5hdr *hdr, const char *buffer,
                              size_t size)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(hdr, buffer, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

/* put socks5 ATYPE, ADDR and PORT to buffer
   addr could be either domain or ipv4/6 address presented in string */
static ssize_t socks5_addr_put(char *buffer, size_t size,
                               const struct socks5addr *addr)
{
    size_t offset = 0;
    struct in_addr in4;
    struct in6_addr in6;
    uint8_t atype, alen;
    const void *aptr;
    uint16_t portbe = htobe16(addr->port);

    /* determine address type and length */
    if (inet_pton(AF_INET, addr->addr, &in4) == 1) {
        atype = SOCKS5_ATYPE_INET4;
        alen = sizeof(in4);
        aptr = &in4;
    } else if (inet_pton(AF_INET6, addr->addr, &in6) == 1) {
        atype = SOCKS5_ATYPE_INET6;
        alen = sizeof(in6);
        aptr = &in6;
    } else {
        atype = SOCKS5_ATYPE_DOMAIN;
        alen = strlen(addr->addr);
        aptr = addr->addr;
    }

    /* check buffer is big enough */
    if (atype == SOCKS5_ATYPE_DOMAIN) {
        if (sizeof(atype) + sizeof(alen) + alen + sizeof(portbe) > size)
            return -1;
    } else {
        if (sizeof(atype) + alen + sizeof(portbe) > size)
            return -1;
    }

    /* copy to buffer */
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

/* get socks5 address from buffer, buffer should pointing to ATYPE
   if ATYPE is ipv4/v6 address, this function will return string representation
 */
static ssize_t socks5_addr_get(struct socks5addr *addr, const char *buffer,
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

        inet_ntop(AF_INET, &in4, addr->addr, sizeof(addr->addr));
        break;

    case SOCKS5_ATYPE_INET6:
        if (cur - buffer + sizeof(in6) > size)
            return -1;
        memcpy(&in6, cur, sizeof(in6));
        cur += sizeof(in6);

        inet_ntop(AF_INET6, &in6, addr->addr, sizeof(addr->addr));
        break;

    case SOCKS5_ATYPE_DOMAIN:
        if (cur - buffer + sizeof(alen) > size)
            return -1;
        memcpy(&alen, cur, sizeof(alen));
        cur += sizeof(alen);

        if (cur - buffer + alen > (ssize_t)size)
            return -1;
        memset(addr->addr, 0, sizeof(addr->addr));
        memcpy(addr->addr, cur, alen);
        cur += alen;
        break;

    default:
        return -1;
    }

    if (cur - buffer + sizeof(portbe) > size)
        return -1;
    memcpy(&portbe, cur, sizeof(portbe));
    cur += sizeof(portbe);

    addr->port = be16toh(portbe);

    return cur - buffer;
}

/* epoll event callback used after handshake
   we don't care events after handshaked, just forward event to user */
void socks_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *self =
        container_of(poller, struct conn_socks, io_poller);
    self->userev(self->userp, event);
}

/* epoll event callback
   used of receiving socks handshake reply */
void socks_handshake_phase_4(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *self =
        container_of(poller, struct conn_socks, io_poller);
    struct socks5hdr hdr;
    struct socks5addr ad;
    ssize_t s, nread;
    int pass; /* did handshake finished? */

    if (event & (EPOLLERR | EPOLLHUP)) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* use MSG_PEEK here, if some application layer data has been returned,
       we can carefuly not to touch them
    */
    if ((nread = recv(self->sfd, self->buffer + self->nbuffer,
                      sizeof(self->buffer) - self->nbuffer - 1, MSG_PEEK)) ==
        -1) {
        if (!is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        /* */
        return;
    }

    /* determine whether handshake finished, and boundary of handshake message
     */
    do {
        ssize_t ret, offset = 0;

        s = nread;
        pass = 0;

        ret = socks5_hdr_get(&hdr, self->buffer + offset,
                             self->nbuffer + nread - offset);
        if (ret == -1)
            break;
        offset += ret;

        ret = socks5_addr_get(&ad, self->buffer + offset,
                              self->nbuffer + nread - offset);
        if (ret == -1)
            break;
        offset += ret;

        s = offset - self->nbuffer;
        pass = 1;
    } while (0);

    /* discard socks handshake reply part in socket buffer */
    if ((nread = recv(self->sfd, self->buffer + self->nbuffer, s, 0)) != s) {
        fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, s);
        abort();
    }
    self->nbuffer += nread;

    /* handshake not finished */
    if (!pass) {
        /* failed, handshake not finished but connection lost or buffer full */
        if (s == 0 || self->nbuffer == sizeof(self->buffer))
            self->userev(self->userp, EPOLLERR);

        /* if not failed, wait for rest handshake message */
        return;
    }

    if (hdr.ver != 5 || hdr.rsp != 0) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    loglv(1, "Connected to tcp:%s:%u", self->addr, (unsigned)self->port);

    /* good, handshake finish, listen and forward epoll event for user */
    self->io_poller_ev.events = EPOLLIN | EPOLLOUT;
    self->io_poller.on_epoll_event = &socks_io_event;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* epoll event callback
   used of sending socks handshake request */
void socks_handshake_phase_3(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *self =
        container_of(poller, struct conn_socks, io_poller);
    ssize_t nsent;

    if (event & (EPOLLERR | EPOLLHUP)) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* it's first called to this function, fill buffer */
    if (self->nbuffer == 0) {
        struct socks5hdr hdr = { .ver = 5, .cmd = SOCKS5_CMD_CONNECT };
        struct socks5addr ad;
        ssize_t ret;

        strncpy(ad.addr, self->addr, sizeof(ad.addr) - 1);
        ad.port = self->port;

        ret = socks5_hdr_put(self->buffer + self->nbuffer,
                             sizeof(self->buffer) - self->nbuffer, &hdr);
        if (ret == -1) {
            self->userev(self->userp, EPOLLERR);
            return;
        }
        self->nbuffer += ret;

        ret = socks5_addr_put(self->buffer + self->nbuffer,
                              sizeof(self->buffer) - self->nbuffer, &ad);
        if (ret == -1) {
            self->userev(self->userp, EPOLLERR);
            return;
        }
        self->nbuffer += ret;
    }

    if ((nsent = send(self->sfd, self->buffer, self->nbuffer, MSG_NOSIGNAL)) ==
        -1) {
        if (!is_ignored_skerr(errno)) {
            perror("send()");
            abort();
        }
        return; /* will handle in error handle */
    }
    self->nbuffer -= nsent;

    /* partial write, wait next time to write rest */
    if (self->nbuffer != 0) {
        memmove(self->buffer, self->buffer + nsent, self->nbuffer);
        return;
    }

    /* good, request has been sent */
    self->io_poller_ev.events = EPOLLIN;
    self->io_poller.on_epoll_event = &socks_handshake_phase_4;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* epoll event callback
   used of receiving socks handshake method */
void socks_handshake_phase_2(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *self =
        container_of(poller, struct conn_socks, io_poller);
    ssize_t nread;

    if (event & (EPOLLERR | EPOLLHUP)) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    if ((nread = recv(self->sfd, self->buffer + self->nbuffer,
                      sizeof(self->buffer) - self->nbuffer, 0)) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("recv()");
            abort();
        }
        return;
    }
    self->nbuffer += nread;

    /* if nbuffer == 0, handshake failed because EOF
       if nbuffer > 2, hanshake failed because server didn't follow RFC1928
    */
    if (self->nbuffer == 0 || self->nbuffer > 2) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* wait more data */
    if (self->nbuffer != 2)
        return;

    if (self->buffer[0] != 5 || self->buffer[1] != 0) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* good, server replied correctly */
    self->nbuffer = 0;
    self->io_poller_ev.events = EPOLLOUT;
    self->io_poller.on_epoll_event = &socks_handshake_phase_3;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* epoll event callback
   used of sending socks handshake method */
void socks_handshake_phase_1(struct ep_poller *poller, unsigned int event)
{
    struct conn_socks *self =
        container_of(poller, struct conn_socks, io_poller);
    ssize_t nsent;

    if (event & (EPOLLERR | EPOLLHUP)) {
        self->userev(self->userp, EPOLLERR);
        return;
    }

    /* it's first called to this function, assembly request */
    if (self->nbuffer == 0) {
        if (sizeof(self->buffer) < 3) {
            self->userev(self->userp, EPOLLERR);
            return;
        }
        /* current only support no auth */
        self->buffer[self->nbuffer++] = 5; /* ver */
        self->buffer[self->nbuffer++] = 1; /* num */
        self->buffer[self->nbuffer++] = 0; /* no auth */
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

    /* good, method has been send */
    self->io_poller_ev.events = EPOLLIN;
    self->io_poller.on_epoll_event = &socks_handshake_phase_2;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }
}

/* impl for struct sk_ops :: connect
   the argument addr and port is proxied connection, not proxy server
*/
int socks_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    struct loopconf *conf = loop_conf(self->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int sktype = self->isudp ? SOCK_DGRAM : SOCK_STREAM;
    int const enable = 1;

    if (strlen(addr) >= 128)
        return -1;

    /* connect to proxy server,
       save arguments addr and port, there are required in handshake */
    getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result);

    if ((self->sfd = socket(result->ai_family,
                            sktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        abort();
    }

    if (!self->isudp) {
        if (setsockopt(self->sfd, IPPROTO_TCP, TCP_NODELAY, &enable,
                       sizeof(int)) == -1) {
            perror("setsockopt()");
            abort();
        }
    }

    if (connect(self->sfd, result->ai_addr, result->ai_addrlen) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("connect()");
            abort();
        }
    }

    freeaddrinfo(result);

    if (self->isudp) {
        /* it's no need to handshake in udp, start forward packet now */
        loglv(1, "Forwarding udp:%s:%u", addr, (unsigned)port);
        self->io_poller.on_epoll_event = &socks_io_event;
        self->io_poller_ev.events = EPOLLOUT | EPOLLIN;
    } else {
        self->io_poller.on_epoll_event = &socks_handshake_phase_1;
        self->io_poller_ev.events = EPOLLOUT;
    }

    self->io_poller_ev.data.ptr = &self->io_poller;
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
int socks_shutdown(struct sk_ops *conn, int how)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    int ret;

    if (self->io_poller.on_epoll_event != &socks_io_event) {
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
void socks_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    unsigned int old = self->io_poller_ev.events;

    if (self->io_poller.on_epoll_event != &socks_io_event) {
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
ssize_t socks_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    ssize_t nsent;

    /* handshake is not finished */
    if (self->io_poller.on_epoll_event != &socks_io_event) {
        return -EAGAIN;
    }

    /* udp, send a header before send actual data used MSG_MORE */
    if (self->isudp) {
        char buffer[512];
        struct socks5hdr hdr = { 0 };
        struct socks5addr addr;
        size_t offset = 0;
        ssize_t ret;

        strncpy(addr.addr, self->addr, sizeof(addr.addr) - 1);
        addr.port = self->port;

        ret = socks5_hdr_put(buffer + offset, sizeof(buffer) - offset, &hdr);
        offset += ret;

        ret = socks5_addr_put(buffer + offset, sizeof(buffer) - offset, &addr);
        offset += ret;

        /* assumed max udp packet payload length is (65535 - 8 - 40),
           and socks5 header takes some space, check it
        */
        if (offset + size > 65535 - 8 - 40)
            return -E2BIG;

        nsent = send(self->sfd, buffer, offset, MSG_NOSIGNAL | MSG_MORE);
        if (nsent == -1) {
            if (is_ignored_skerr(errno)) {
                return -errno; /* return imm */
            } else {
                perror("send()");
                abort();
            }
        }
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

    loglv(3, "--- socks %zd bytes. %s:%s:%u", nsent,
          self->isudp ? "udp" : "tcp", self->addr, (unsigned)self->port);

    return nsent;
}

/* impl for struct sk_ops :: recv */
ssize_t socks_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    ssize_t nread;

    /* handshake is not finished */
    if (self->io_poller.on_epoll_event != &socks_io_event) {
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

    loglv(3, "+++ socks %zd bytes. %s:%s:%u", nread,
          self->isudp ? "udp" : "tcp", self->addr, (unsigned)self->port);

    /* is udp, parse and remove header */
    if (self->isudp) {
        struct socks5hdr hdr;
        struct socks5addr ad;
        ssize_t ret, offset = 0;

        /* if it's a bad packet, drop ,and return -EAGAIN to tell user to retry
         */

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

/* impl for struct sk_ops :: destory */
void socks_destroy(struct sk_ops *conn)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);

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

    if (self->io_poller.on_epoll_event == &socks_io_event) {
        loglv(2, "Closed %s:%u", self->addr, (unsigned)self->port);
    } else {
        loglv(0, "FAILED to connect proxy server.");
    }

    if (close(self->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(self->addr);

    free(self);
}

/* used for internal only */
struct conn_socks *socks_create_internal()
{
    struct conn_socks *self;

    if ((self = calloc(1, sizeof(struct conn_socks))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->ops.connect = &socks_connect;
    self->ops.shutdown = &socks_shutdown;
    self->ops.evctl = &socks_evctl;
    self->ops.send = &socks_send;
    self->ops.recv = &socks_recv;
    self->ops.destroy = &socks_destroy;

    return self;
}

/* create a tcp connection
   this connection is proxied via socks server */
struct sk_ops *socks_tcp_create(struct loopctx *loop,
                                void (*userev)(void *userp, unsigned int event),
                                void *userp)
{
    struct conn_socks *self = socks_create_internal();

    self->isudp = 0;
    self->loop = loop;
    self->userev = userev;
    self->userp = userp;
    return &self->ops;
}

/* create a udp connection
   this connection is proxied via socks server */
struct sk_ops *socks_udp_create(struct loopctx *loop,
                                void (*userev)(void *userp, unsigned int event),
                                void *userp)
{
    struct conn_socks *self = socks_create_internal();

    self->isudp = 1;
    self->loop = loop;
    self->userev = userev;
    self->userp = userp;
    return &self->ops;
}

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

/* socks handshake phases */
enum {
    PHASE_SEND_METHOD = 1,
    PHASE_RECV_METHOD,
    PHASE_SEND_AUTH,
    PHASE_RECV_AUTH,
    PHASE_SEND_REQUEST,
    PHASE_RECV_REPLY,
    PHASE_FORWARDING,
};

static const char *phasestr[] = {
    [PHASE_SEND_METHOD] = "PHASE_SEND_METHOD",
    [PHASE_RECV_METHOD] = "PHASE_RECV_METHOD",
    [PHASE_SEND_AUTH] = "PHASE_SEND_AUTH",
    [PHASE_RECV_AUTH] = "PHASE_RECV_AUTH",
    [PHASE_SEND_REQUEST] = "PHASE_SEND_REQUEST",
    [PHASE_RECV_REPLY] = "PHASE_RECV_REPLY",
    [PHASE_FORWARDING] = "PHASE_FORWARDING",
};

static const char *rspstr[] = {
    [0] = "Succeeded",
    [1] = "General SOCKS server failure",
    [2] = "Connection not allowed by ruleset",
    [3] = "Network unreachable",
    [4] = "Host unreachable",
    [5] = "Connection refused",
    [6] = "TTL expired",
    [7] = "Command not supported",
    [8] = "Address type not supported",
    [9] = "Unassigned",
};

enum {
    TCP_FORWARD,   /* TCP connection forwarding */
    UDP_FORWARD,   /* UDP packet forwarding (client side) */
    UDP_ASSOCIATE,   /* UDP association control connection */
};

struct conn_socks {
    struct sk_ops ops;
    struct loopctx *loop;

    struct epcb_ops epcb;

    int refcnt;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    char *addr; /* for proxied connection, not proxy server */
    uint16_t port;

    /* - TCP_FORWARD: connected to proxy, for both handshake and data foward
     * - UDP_FORWARD: connected to relay server, for UDP foward only
     * - UDP_ASSOCIATE: connected to proxy, for UDP associate handshake only
     */
    int type;

    int sfd;
    unsigned int events;

    int phase;

    /* for handshake only */
    /* TODO: free these buffer after handshake finished */
    char buffer[512];
    size_t nbuffer;

    size_t nsent;
    size_t nread;
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

static void socks_handshake_output(struct conn_socks *self)
{
    struct loopconf *conf = loop_conf(self->loop);
    ssize_t nsent;

    /* it's first called to this phase, assembly buffer */
    if (self->nbuffer == 0) {
        if (self->phase == PHASE_SEND_METHOD) {
            static_assert(sizeof(self->buffer) >= 4, "???");

            self->buffer[self->nbuffer++] = 5; /* ver */
            if (conf->proxyuser[0] != '\0') {
                self->buffer[self->nbuffer++] = 2; /* num methods */
                self->buffer[self->nbuffer++] = 0; /* no auth */
                self->buffer[self->nbuffer++] = 2; /* user/pass auth */
            } else {
                self->buffer[self->nbuffer++] = 1; /* num methods */
                self->buffer[self->nbuffer++] = 0; /* no auth */
            }
        }
        if (self->phase == PHASE_SEND_AUTH) {
            size_t ulen = strlen(conf->proxyuser);
            size_t plen = strlen(conf->proxypass);

            static_assert(sizeof(self->buffer) >= sizeof(conf->proxyuser)
                              + sizeof(conf->proxypass) + 2, "????");

            self->buffer[self->nbuffer++] = 1; /* ver */
            self->buffer[self->nbuffer++] = (uint8_t)ulen;
            memcpy(self->buffer + self->nbuffer, conf->proxyuser, ulen);
            self->nbuffer += ulen;
            self->buffer[self->nbuffer++] = (uint8_t)plen;
            memcpy(self->buffer + self->nbuffer, conf->proxypass, plen);
            self->nbuffer += plen;
        }
        if (self->phase == PHASE_SEND_REQUEST) {
            struct socks5hdr hdr = { .ver = 5, .cmd = SOCKS5_CMD_CONNECT };
            struct socks5addr ad;
            ssize_t ret;

            static_assert(sizeof(self->buffer) >= sizeof(hdr) + sizeof(ad.addr)
                              + 3, "???");

            strlcpy(ad.addr, self->addr, sizeof(ad.addr));
            ad.port = self->port;

            ret = socks5_hdr_put(self->buffer + self->nbuffer,
                                 sizeof(self->buffer) - self->nbuffer, &hdr);
            if (ret == -1) {
                fprintf(stderr, "an invariant violation has been detected.\n");
                abort();
            }
            self->nbuffer += ret;

            ret = socks5_addr_put(self->buffer + self->nbuffer,
                                  sizeof(self->buffer) - self->nbuffer, &ad);
            if (ret == -1) {
                fprintf(stderr, "an invariant violation has been detected.\n");
                abort();
            }
            self->nbuffer += ret;
        }
    }

    nsent = send(self->sfd, self->buffer, self->nbuffer, MSG_NOSIGNAL);
    if (nsent == -1) {
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

    switch (self->phase) {
        case PHASE_SEND_METHOD:  self->phase = PHASE_RECV_METHOD; break;
        case PHASE_SEND_AUTH:    self->phase = PHASE_RECV_AUTH;   break;
        case PHASE_SEND_REQUEST: self->phase = PHASE_RECV_REPLY;  break;
    }

    loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLIN, &self->epcb);
}

static void socks_handshake_input(struct conn_socks *self)
{
    ssize_t nread;

    if (self->phase == PHASE_RECV_METHOD) {
        nread = recv(self->sfd, self->buffer + self->nbuffer,
                     sizeof(self->buffer) - self->nbuffer, 0);
        if (nread == -1) {
            if (!is_ignored_skerr(errno)) {
                perror("recv()");
                abort();
            }
            return;
        }
        if (nread == 0) {
            loglv(0, "Proxy server closed connection unexpectedly during "
                     "method negotiation");
            self->userev(self->userp, EPOLLERR);
            return;
        }
        self->nbuffer += nread;

        /* wait more data */
        if (self->nbuffer < 2)
            return;

        /* no a correct protocol header */
        if (self->buffer[0] != 5) {
            loglv(0, "Proxy server retern a bad reply: VER field is 0x%02x, "
                     "expected 0x05", (unsigned char)self->buffer[0]);
            self->userev(self->userp, EPOLLERR);
            return;
        }

        /* server reject our all method */
        if ((unsigned char)self->buffer[1] == 0xFF) {
            loglv(0, "Proxy server requires authentication. "
                     "Please check your username and password.");
            self->userev(self->userp, EPOLLERR);
            return;
        } /* - else: server selected a method */

        /* should be only one method */
        if (self->nbuffer != 2) {
            loglv(0, "Proxy server returned invalid method response");
            self->userev(self->userp, EPOLLERR);
            return;
        }

        /* see what method server selected */
        if (self->buffer[1] == 2) {
            /* username password auth */
            self->phase = PHASE_SEND_AUTH;
        } else if (self->buffer[1] == 0) {
            /* no auth */
            self->phase = PHASE_SEND_REQUEST;
        } else {
            /* other */
            loglv(0, "Proxy server returned unsupported authentication "
                     "method: 0x%02x", (unsigned char)self->buffer[1]);
            self->userev(self->userp, EPOLLERR);
            return;
        }
    }

    if (self->phase == PHASE_RECV_AUTH) {
        nread = recv(self->sfd, self->buffer + self->nbuffer,
                     sizeof(self->buffer) - self->nbuffer, 0);
        if (nread == -1) {
            if (!is_ignored_skerr(errno)) {
                perror("recv()");
                abort();
            }
            return;
        }
        self->nbuffer += nread;

        /* if nbuffer == 0, handshake failed because EOF
           if nbuffer > 2, hanshake failed because server didn't follow RFC1929
        */
        if (self->nbuffer == 0 || self->nbuffer > 2) {
            if (self->nbuffer == 0) {
                loglv(0, "Proxy server closed connection unexpectedly during "
                         "authentication");
            } else {
                loglv(0, "Proxy server returned invalid auth response");
            }
            self->userev(self->userp, EPOLLERR);
            return;
        }

        /* wait more data */
        if (self->nbuffer != 2)
            return;

        if (self->buffer[0] != 1 || self->buffer[1] != 0) {
            loglv(0, "SOCKS5 authentication failed. "
                     "Please check your username and password.");
            self->userev(self->userp, EPOLLERR);
            return;
        }

        /* good, server replied correctly */
        self->phase = PHASE_SEND_REQUEST;
    }


    if (self->phase == PHASE_RECV_REPLY) {
        struct socks5hdr hdr = { 0 };
        struct socks5addr ad;
        ssize_t s;
        int pass; /* did handshake finished? */

        /* use MSG_PEEK here, if some application layer data has been returned,
           we can carefuly not to touch them */
        nread = recv(self->sfd, self->buffer + self->nbuffer,
                     sizeof(self->buffer) - self->nbuffer - 1, MSG_PEEK);
        if (nread == -1) {
            if (!is_ignored_skerr(errno)) {
                perror("recv()");
                abort();
            }
            return;
        }

        /* determine whether handshake finished, and boundary of handshake
           message */
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
        nread = recv(self->sfd, self->buffer + self->nbuffer, s, 0);
        if (nread != s) {
            fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, s);
            abort();
        }
        self->nbuffer += nread;

        /* handshake not finished */
        if (!pass) {
            /* failed, handshake not finished but connection lost or buffer
               full */
            if (s == 0 || self->nbuffer == sizeof(self->buffer)) {
                loglv(0, "Proxy server returned a header that is too large "
                         "during the handshake.");
                self->userev(self->userp, EPOLLERR);
            }

            /* if not failed, wait for rest handshake message */
            return;
        }

        if (hdr.ver != 5) {
            loglv(0, "Proxy server retern a bad reply: VER field is 0x%02x, "
                     "expected 0x05", hdr.ver);
            self->userev(self->userp, EPOLLERR);
            return;
        }

        if (hdr.rsp != 0) {
            if (hdr.rsp == 2) {
                loglv(0, "Proxy server rejected our request: %s. "
                         "Please check your username and password.",
                         rspstr[2]);
            } else {
                loglv(0, "Proxy server rejected our request: %s",
                         hdr.rsp > 9 ? rspstr[9] : rspstr[hdr.rsp]);
            }
            self->userev(self->userp, EPOLLERR);
            return;
        }

        self->phase = PHASE_FORWARDING;
        loglv(1, "Connected %s:%u/tcp", self->addr, (unsigned)self->port);
    }

    /* clear input buffer */
    self->nbuffer = 0;

    /* when control flow reach here, it should finish a step of input phase */
    if (self->phase == PHASE_SEND_REQUEST || self->phase == PHASE_SEND_AUTH) {
        loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLOUT,
                       &self->epcb);
    } else {
        assert(self->phase == PHASE_FORWARDING);
        loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLOUT | EPOLLIN,
                       &self->epcb);
    }
}

static void socks_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct conn_socks *self =
        container_of(epcb, struct conn_socks, epcb);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events);
        return;
    }

    loglv(3, "socks_epcb_events: handshaking with %s:%u/%s [%s]",
             self->addr, (unsigned)self->port,
             self->type == TCP_FORWARD ? "tcp" : "udp", phasestr[self->phase]);

    if ((events & (EPOLLERR | EPOLLHUP)) && !(events & EPOLLIN)) {
        loglv(0, "Proxy connection closed unexpectedly during SOCKS handshake "
                 "phase [%s]", phasestr[self->phase]);
        self->userev(self->userp, EPOLLERR);
        return;
    }

    if (self->phase == PHASE_SEND_METHOD || self->phase == PHASE_SEND_AUTH ||
        self->phase == PHASE_SEND_REQUEST) {
        socks_handshake_output(self);
    } else {
        socks_handshake_input(self);
    }
}

/* impl for struct sk_ops :: connect
   the argument addr and port is proxied connection, not proxy server
*/
static int socks_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    struct loopconf *conf = loop_conf(self->loop);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    int sktype = self->type == UDP_FORWARD ? SOCK_DGRAM : SOCK_STREAM;
    int const enable = 1;

    loglv(3, "socks_connect: connecting %s:%u/%s",
             addr, (unsigned)port, self->type == TCP_FORWARD ? "tcp" : "udp");

    if (strlen(addr) >= 128)
        return -1;

    /* connect to proxy server,
       save arguments addr and port, there are required in handshake */
    if (getaddrinfo(conf->proxysrv, conf->proxyport, &hints, &result) != 0)
        return -1;

    if ((self->sfd = socket(result->ai_family,
                            sktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        abort();
    }

    if (self->type != UDP_FORWARD) {
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

    if (self->type == UDP_FORWARD) {
        /* it's no need to handshake in udp, start forward packet now */
        self->phase = PHASE_FORWARDING;
        loglv(1, "Forwarding %s:%u/udp", addr, (unsigned)port);
        loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, EPOLLOUT | EPOLLIN,
                       &self->epcb);
    } else {
        self->phase = PHASE_SEND_METHOD;
        loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, EPOLLOUT,
                       &self->epcb);
    }

    self->addr = strdup(addr);
    self->port = port;

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int socks_shutdown(struct sk_ops *conn, int how)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    int ret;

    loglv(3, "socks_shutdown: shutting down %s:%u/%s", self->addr,
             (unsigned)self->port, self->type == TCP_FORWARD ? "tcp" : "udp");

    if (self->phase != PHASE_FORWARDING) {
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
static void socks_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    unsigned int new_events = self->events;

    if (self->phase != PHASE_FORWARDING) {
        return;
    }

    if (enable) {
        new_events |= event;
    } else {
        new_events &= ~event;
    }

    if (new_events != self->events)
        loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, new_events,
                       &self->epcb);
}

/* impl for struct sk_ops :: send */
static ssize_t socks_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    char buffer[512]; /* for socks header only  */
    struct msghdr msg;
    struct iovec iov[2];
    size_t iovlen = 0;
    ssize_t nsent;

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    if (self->type == UDP_FORWARD) {
        struct socks5hdr hdr = { 0 };
        struct socks5addr addr;
        size_t offset = 0;
        ssize_t ret;

        strlcpy(addr.addr, self->addr, sizeof(addr.addr));
        addr.port = self->port;

        ret = socks5_hdr_put(buffer + offset, sizeof(buffer) - offset, &hdr);
        offset += ret;

        ret = socks5_addr_put(buffer + offset, sizeof(buffer) - offset, &addr);
        offset += ret;

        iov[iovlen].iov_base = buffer;
        iov[iovlen].iov_len = offset;
        iovlen++;
    }

    iov[iovlen].iov_base = (void *)data;
    iov[iovlen].iov_len = size;
    iovlen++;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = iovlen;

    nsent = sendmsg(self->sfd, &msg, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    self->nsent += nsent;
    loglv(2, "--- socks %zd bytes. %s:%u/%s", nsent, self->addr,
             (unsigned)self->port, self->type == TCP_FORWARD ? "tcp" : "udp");

    return nsent;
}

/* impl for struct sk_ops :: recv */
static ssize_t socks_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    ssize_t nread;

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
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

    self->nread += nread;
    loglv(2, "+++ socks %zd bytes. %s:%u/%s", nread, self->addr,
             (unsigned)self->port, self->type == TCP_FORWARD ? "tcp" : "udp");

    /* is udp, parse and remove header */
    if (self->type == UDP_FORWARD) {
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

/* internal destroy function, called when refcnt reaches zero */
static void socks_destroy_internal(struct conn_socks *self)
{
    loglv(3, "socks_destroy_internal: destroying %s:%u/%s", self->addr,
             (unsigned)self->port, self->type == TCP_FORWARD ? "tcp" : "udp");

    loop_epoll_ctl(self->loop, EPOLL_CTL_DEL, self->sfd, 0, NULL);

    if (shutdown(self->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    if (self->phase == PHASE_FORWARDING) {
        loglv(1, "Closed %s:%u (sent %zu, recieved %zu bytes)",
                 self->addr, (unsigned)self->port, self->nsent, self->nread);
    }

    if (close(self->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(self->addr);

    free(self);
}

/* impl for struct sk_ops :: get */
static void socks_get(struct sk_ops *conn)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    loglv(3, "socks_get: refcnt %d -> %d", self->refcnt, self->refcnt + 1);
    self->refcnt++;
}

/* impl for struct sk_ops :: put */
static void socks_put(struct sk_ops *conn)
{
    struct conn_socks *self = container_of(conn, struct conn_socks, ops);
    loglv(3, "socks_put: refcnt %d -> %d", self->refcnt, self->refcnt - 1);
    if (--self->refcnt == 0) {
        socks_destroy_internal(self);
    }
}

/* used for internal only */
static struct conn_socks *socks_create_internal(void)
{
    struct conn_socks *self;

    loglv(3, "socks_create_internal: creating a new struct conn_socks");

    if ((self = calloc(1, sizeof(struct conn_socks))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->ops.connect = &socks_connect;
    self->ops.shutdown = &socks_shutdown;
    self->ops.evctl = &socks_evctl;
    self->ops.send = &socks_send;
    self->ops.recv = &socks_recv;
    self->ops.get = &socks_get;
    self->ops.put = &socks_put;
    self->epcb.on_epoll_events = &socks_epcb_events;

    self->sfd = -1;
    self->refcnt = 1;

    return self;
}

/* create a tcp connection
   this connection is proxied via socks server */
struct sk_ops *socks_tcp_create(struct loopctx *loop,
                                void (*userev)(void *userp, unsigned int event),
                                void *userp)
{
    struct conn_socks *self = socks_create_internal();

    self->type = TCP_FORWARD;
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

    self->type = UDP_FORWARD;
    self->loop = loop;
    self->userev = userev;
    self->userp = userp;
    return &self->ops;
}

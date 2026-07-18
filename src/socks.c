/*
 * Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "socks.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "loop.h"
#include "skutils.h"

#define SOCKS_HS_BUFF 1024

/* socks handshake phases */
enum {
    PHASE_FAILED = 0,
    PHASE_SEND_METHOD,
    PHASE_RECV_METHOD,
    PHASE_SEND_AUTH,
    PHASE_RECV_AUTH,
    PHASE_SEND_REQUEST,
    PHASE_RECV_REPLY,
    PHASE_FORWARDING,
};

static const char *phasestr[] = {
    [PHASE_SEND_METHOD] = "send-method",
    [PHASE_RECV_METHOD] = "recv-method",
    [PHASE_SEND_AUTH] = "send-auth",
    [PHASE_RECV_AUTH] = "recv-auth",
    [PHASE_SEND_REQUEST] = "send-request",
    [PHASE_RECV_REPLY] = "recv-reply",
    [PHASE_FORWARDING] = "forwarding",
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

/* - TCP_FORWARD: connected to proxy, for TCP only
 * - UDP_FORWARD: connected to relay server, for UDP foward only
 * - UDP_ASSOCIATE: connected to proxy, for UDP associate handshake only
 */
enum {
    TCP_FORWARD,
    UDP_FORWARD,
    UDP_ASSOCIATE,
};

struct reladdr {
    char addr[SERVNAME_MAXLEN + 1];
    uint16_t port;
};

struct proxy_socks {
    struct proxy ops;

    /* loop */
    struct loopctx *loop;
    struct epcb_ops epcb;

    /* socket */
    int sfd;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;

    /* target */
    char ip[IP_MAXLEN + 1];
    uint16_t port;

    /* info */
    struct skinfo info;

    /* handshake */
    int type; /* TCP_FORWARD / UDP_FORWARD / UDP_ASSOCIATE */
    int phase;
    struct buff *hsbuff;

    /* for udp forward only */
    struct reladdr *relay;
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

    addr->port = ntohs(portbe);

    return cur - buffer;
}

/* Resolve address in socks5addr to IP string presentation.
   Most servers fills IP in BND.ADDR, but we allow domain per RFC. Resolution
   briefly blocks the event loop, but usually only once and not harmful.
   Return 0 if OK, -1 if failed. */
static int socks5_set_reladdr(struct reladdr *dst, struct socks5addr *src)
{
    char port[8];
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *res = NULL;

    static_assert(sizeof(dst->addr) >= sizeof(current_nspconf()->proxysrv)
                  && sizeof(dst->addr) >= INET6_ADDRSTRLEN, "???");

    snprintf(port, sizeof(port), "%u", (unsigned)src->port);
    if (getaddrinfo(src->addr, port, &hints, &res) != 0)
        goto failed_after_getaddrinfo;

    if (res->ai_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(res->ai_family, &sa4->sin_addr, dst->addr, sizeof(dst->addr));
        dst->port = ntohs(sa4->sin_port);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(res->ai_family, &sa6->sin6_addr, dst->addr, sizeof(dst->addr));
        dst->port = ntohs(sa6->sin6_port);
    } else {
        goto failed_after_getaddrinfo;
    }

    /* reladdr.addr is all zero, means relay address is same as proxy address */
    if (strcmp(dst->addr, "0.0.0.0") == 0 || strcmp(dst->addr, "::") == 0) {
        strcpy(dst->addr, current_nspconf()->proxysrv); /* static_assert checked */
        dst->port = src->port;
    }

    freeaddrinfo(res);
    return 0;

failed_after_getaddrinfo:
    if (res)
        freeaddrinfo(res);
    return -1;
}

static void socks_handshake_perror(struct proxy_socks *self, int err)
{
    if (err > 0)
        loglv0("Proxy server reset unexpectedly during SOCKS5 handshake phase "
               "[%s]: %s", phasestr[self->phase], strerror(err));
    else
        loglv0("Proxy server closed unexpectedly during SOCKS5 handshake phase "
               "[%s]", phasestr[self->phase]);
}

static void socks_handshake_output(struct proxy_socks *self)
{
    struct nspconf *conf = current_nspconf();
    ssize_t nsent;
    struct buff *buff = self->hsbuff;

    /* it's first called to this phase, assembly buffer */
    if (buff->size == 0) {
        if (self->phase == PHASE_SEND_METHOD) {
            buff->data[buff->size++] = 5; /* ver */
            if (conf->proxyuser[0] != '\0') {
                buff->data[buff->size++] = 2; /* num methods */
                buff->data[buff->size++] = 0; /* no auth */
                buff->data[buff->size++] = 2; /* user/pass auth */
            } else {
                buff->data[buff->size++] = 1; /* num methods */
                buff->data[buff->size++] = 0; /* no auth */
            }
        }
        if (self->phase == PHASE_SEND_AUTH) {
            size_t ulen = strlen(conf->proxyuser);
            size_t plen = strlen(conf->proxypass);

            buff->data[buff->size++] = 1; /* ver */
            buff->data[buff->size++] = (uint8_t)ulen;
            memcpy(buff->data + buff->size, conf->proxyuser, ulen);
            buff->size += ulen;
            buff->data[buff->size++] = (uint8_t)plen;
            memcpy(buff->data + buff->size, conf->proxypass, plen);
            buff->size += plen;
        }
        if (self->phase == PHASE_SEND_REQUEST) {
            struct socks5hdr hdr;
            struct socks5addr ad;
            ssize_t ret;

            hdr.ver = 0x5;
            hdr.cmd = self->type == TCP_FORWARD ? SOCKS5_CMD_CONNECT
                                                : SOCKS5_CMD_UDPASSOC;
            hdr.rsv = 0x0;

            snprintf(ad.addr, sizeof(ad.addr), "%s", self->ip);
            ad.port = self->port;

            ret = socks5_hdr_put(buff->data + buff->size,
                                 buff->capacity - buff->size, &hdr);
            assert(ret > 0);
            buff->size += ret;

            ret = socks5_addr_put(buff->data + buff->size,
                                  buff->capacity - buff->size, &ad);
            assert(ret > 0);
            buff->size += ret;
        }
    }

    nsent = send(self->sfd, buff->data, buff->size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno != EAGAIN) {
            socks_handshake_perror(self, errno);
            self->phase = PHASE_FAILED;
            self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
        }
        return;
    }
    buff->size -= nsent;

    if (buff->size != 0) {
        /* partial write, wait next time to write rest */
        memmove(buff->data, buff->data + nsent, buff->size);
        return;
    }

    switch (self->phase) {
        case PHASE_SEND_METHOD:  self->phase = PHASE_RECV_METHOD; break;
        case PHASE_SEND_AUTH:    self->phase = PHASE_RECV_AUTH;   break;
        case PHASE_SEND_REQUEST: self->phase = PHASE_RECV_REPLY;  break;
    }

    skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb, EPOLLIN,
                  EVUPD);
}

static void socks_handshake_input(struct proxy_socks *self)
{
    ssize_t nread;
    struct buff *buff = self->hsbuff;

    if (self->phase == PHASE_RECV_METHOD) {
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size, 0);
        if (nread == -1 && errno == EAGAIN) {
            return;
        } else if (nread <= 0) {
            socks_handshake_perror(self, nread == -1 ? errno : 0);
            goto failed_handshake;
        }
        buff->size += nread;

        /* wait more data */
        if (buff->size < 2)
            return;

        /* no a correct protocol header */
        if (buff->data[0] != 5) {
            loglv0("Proxy server return a bad reply: VER field is 0x%02x, "
                   "expected 0x05", (unsigned char)buff->data[0]);
            goto failed_handshake;
        }

        /* server reject our all method */
        if ((unsigned char)buff->data[1] == 0xFF) {
            loglv0("Proxy server requires authentication. Please check your "
                   "username and password.");
            goto failed_handshake;
        } /* - else: server selected a method */

        /* should be only one method */
        if (buff->size != 2) {
            loglv0("Proxy server returned invalid method response");
            goto failed_handshake;
        }

        /* see what method server selected */
        if (buff->data[1] == 2) {
            /* username password auth */
            self->phase = PHASE_SEND_AUTH;
        } else if (buff->data[1] == 0) {
            /* no auth */
            self->phase = PHASE_SEND_REQUEST;
        } else {
            /* other */
            loglv0("Proxy server returned unsupported authentication method: "
                   "0x%02x", (unsigned char)buff->data[1]);
            goto failed_handshake;
        }
    }

    if (self->phase == PHASE_RECV_AUTH) {
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size, 0);
        if (nread == -1 && errno == EAGAIN) {
            return;
        } else if (nread <= 0) {
            socks_handshake_perror(self, nread == -1 ? errno : 0);
            goto failed_handshake;
        }
        buff->size += nread;

        /* hanshake failed because server didn't follow RFC1929 */
        if (buff->size > 2) {
            loglv0("Proxy server returned invalid auth response");
            goto failed_handshake;
        }

        /* wait more data */
        if (buff->size != 2)
            return;

        if (buff->data[0] != 1 || buff->data[1] != 0) {
            loglv0("SOCKS5 authentication failed. Please check your username "
                   "and password.");
            goto failed_handshake;
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
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size - 1, MSG_PEEK);
        if (nread == -1 && errno == EAGAIN) {
            return;
        } else if (nread <= 0) {
            socks_handshake_perror(self, nread == -1 ? errno : 0);
            goto failed_handshake;
        }

        /* determine whether handshake finished, and boundary of handshake
           message */
        do {
            ssize_t ret, offset = 0;

            s = nread;
            pass = 0;

            ret = socks5_hdr_get(&hdr, buff->data + offset,
                                 buff->size + nread - offset);
            if (ret == -1)
                break;
            offset += ret;

            ret = socks5_addr_get(&ad, buff->data + offset,
                                  buff->size + nread - offset);
            if (ret == -1)
                break;
            offset += ret;

            s = offset - buff->size;
            pass = 1;
        } while (0);

        /* discard socks handshake reply part in socket buffer */
        nread = recv(self->sfd, buff->data + buff->size, s, 0);
        if (nread != s) {
            loglv0("Handshake failed, recv() returned %zd, expected %zd",
                   nread, s);
            goto failed_handshake;
        }
        buff->size += nread;

        /* handshake not finished */
        if (!pass) {
            /* failed, handshake not finished but connection lost or buffer
               full */
            if (buff->size == buff->capacity) {
                loglv0("Proxy server returned a header that is too large "
                       "during the handshake.");
                goto failed_handshake;
            }

            /* if not failed, wait for rest handshake message */
            return;
        }

        if (hdr.ver != 5) {
            loglv0("Proxy server return a bad reply: VER field is 0x%02x, "
                   "expected 0x05", hdr.ver);
            goto failed_handshake;
        }

        if (hdr.rsp != 0) {
            if (hdr.rsp == 2) {
                loglv0("Proxy server rejected our request: %s. Please check "
                       "your username and password.", rspstr[2]);
            } else {
                loglv0("Proxy server rejected our request: %s",
                       hdr.rsp > 9 ? rspstr[9] : rspstr[hdr.rsp]);
            }
            goto failed_handshake;
        }

        if (self->type == UDP_ASSOCIATE) {
            if ((self->relay = calloc(1, sizeof(struct reladdr))) == NULL)
                oom();
            if (socks5_set_reladdr(self->relay, &ad) == -1) {
                free(self->relay);
                self->relay = NULL;
                goto failed_handshake;
            }
            loglv1("SOCKS5 UDP relay address: %s:%u", self->relay->addr,
                   (unsigned)self->relay->port);
        }

        self->phase = PHASE_FORWARDING;
        loglv2("... handshaked %s:%u", self->ip, (unsigned)self->port);
    }

    /* clear input buffer */
    buff->size = 0;

    /* when control flow reach here, it should finish a step of input phase */
    if (self->phase == PHASE_SEND_REQUEST || self->phase == PHASE_SEND_AUTH) {
        skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                      EPOLLOUT, EVUPD);
    } else {
        assert(self->phase == PHASE_FORWARDING);
        skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                      EPOLLOUT | EPOLLIN, EVUPD);
        free(self->hsbuff);
        self->hsbuff = NULL;
    }

    return;

failed_handshake:
    self->phase = PHASE_FAILED;
    self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
}

static void socks_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct proxy_socks *self = container_of(epcb, struct proxy_socks, epcb);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events);
        return;
    } else if (self->phase == PHASE_FAILED) {
        self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
        return;
    }

    loginfo("socks_epcb_events: handshake for %s:%u/%s %s",
            self->ip, (unsigned)self->port,
            self->type == TCP_FORWARD ? "tcp" : "udp", phasestr[self->phase]);

    if (self->phase == PHASE_SEND_METHOD || self->phase == PHASE_SEND_AUTH
        || self->phase == PHASE_SEND_REQUEST) {
        socks_handshake_output(self);
    } else {
        socks_handshake_input(self);
    }
}

/* impl for struct proxy :: shutdown */
static int socks_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    return self->phase != PHASE_FORWARDING
               ? -EAGAIN
               : skutils_shutdown(&self->info, self->loop, &self->sfd, how, rst);
}

/* impl for struct proxy :: evctl */
static int socks_evctl(struct proxy *proxy, unsigned int event, int mode)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    return self->phase != PHASE_FORWARDING
               ? -EAGAIN
               : skutils_evctl(self->loop, self->sfd, &self->events,
                               &self->epcb, event, mode);
}

/* impl for struct proxy :: send */
static ssize_t socks_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);

    if (self->phase == PHASE_FAILED)
        return -ECONNABORTED; /* handshake failed */
    else if (self->phase != PHASE_FORWARDING)
        return -EINPROGRESS; /* handshake is not finished */

    if (self->type == UDP_FORWARD) {
        char buffer[512]; /* for socks header only  */
        struct msghdr msg;
        struct iovec iov[2];
        size_t iovlen = 0;
        struct socks5hdr hdr = { 0 };
        struct socks5addr addr;
        size_t offset = 0;
        ssize_t ret;

        snprintf(addr.addr, sizeof(addr.addr), "%s", self->ip);
        addr.port = self->port;

        ret = socks5_hdr_put(buffer + offset, sizeof(buffer) - offset, &hdr);
        offset += ret;

        ret = socks5_addr_put(buffer + offset, sizeof(buffer) - offset, &addr);
        offset += ret;

        iov[iovlen].iov_base = buffer;
        iov[iovlen].iov_len = offset;
        iovlen++;
        iov[iovlen].iov_base = (void *)data;
        iov[iovlen].iov_len = size;
        iovlen++;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = iovlen;

        return skutils_sendmsg(&self->info, self->sfd, &msg);
    } else {
        return skutils_send(&self->info, self->sfd, data, size);
    }
}

/* impl for struct proxy :: recv */
static ssize_t socks_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);

    if (self->phase == PHASE_FAILED)
        return -ECONNABORTED; /* handshake failed */
    else if (self->phase != PHASE_FORWARDING)
        return -EINPROGRESS; /* handshake is not finished */

    /* for-loop will retry if bad UDP packet has been received,
       I think goto is more readable, but there's always some who don't like it */
    for (;;) {
        ssize_t nread = skutils_recv(&self->info, self->sfd, data, size);
        if (nread < 0)
            return nread;

        /* is udp, parse and remove header */
        if (self->type == UDP_FORWARD) {
            struct socks5hdr hdr;
            struct socks5addr ad;
            ssize_t ret, offs = 0;

            if ((ret = socks5_hdr_get(&hdr, data + offs, nread - offs)) < 0)
                continue; /* bad header, retry */
            offs += ret;

            if ((ret = socks5_addr_get(&ad, data + offs, nread - offs)) < 0)
                continue; /* bad address, retry */
            offs += ret;

            /* RFC1928: an implementation that does not support fragmentation
               MUST drop any datagram whose FRAG field is other than X'00' */
            if (hdr.frag != 0)
                continue; /* frag packet, retry */

            /* good, remove header for user */
            memmove(data, data + offs, nread - offs);
            nread -= offs;
        }

        return nread;
    }
}

/* impl for struct proxy :: get */
static void socks_get(struct proxy *proxy)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    self->refcnt++;
}

/* impl for struct proxy :: put */
static void socks_put(struct proxy *proxy)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    if (--self->refcnt == 0) {
        skutils_close_unreg(&self->info, self->loop, &self->sfd);
        free(self->relay);
        free(self->hsbuff);
        free(self);
    }
}

/* global vtable of proxy_socks */
static const struct proxy_ops socks_ops = {
    .shutdown = &socks_shutdown,
    .evctl = &socks_evctl,
    .send = &socks_send,
    .recv = &socks_recv,
    .get = &socks_get,
    .put = &socks_put,
};

/* used for internal only */
static struct proxy_socks *
socks_create_impl(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  int type, const char *ip, uint16_t port,
                  struct proxy_socks *as)
{
    struct proxy_socks *self;
    struct nspconf *conf = current_nspconf();
    int socktype = (type == UDP_FORWARD) ? SOCK_DGRAM : SOCK_STREAM;

    loginfo("socks_create_impl: creating new struct proxy_socks for %s:%u/%s",
            ip, (unsigned)port, (type == UDP_FORWARD) ? "udp" : "tcp");

    if (strlen(ip) > IP_MAXLEN)
        return NULL;

    if ((self = calloc(1, sizeof(struct proxy_socks))) == NULL)
        oom();

    /* init */
    self->ops.ops = &socks_ops;
    self->loop = loop;
    self->epcb.on_epoll_events = &socks_epcb_events;
    self->sfd = -1;
    self->events = 0;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;
    strcpy(self->ip, ip);
    self->port = port;
    self->type = type;
    self->relay = NULL;
    self->info.proto = self->type == TCP_FORWARD ? "tcp" : "udp";
    self->info.addr = self->ip;
    self->info.port = self->port;

    if (type == UDP_FORWARD) {
        /* create socket and bind to relay server */
        self->sfd = skutils_connect(&self->info, as->relay->addr,
                                    as->relay->port, SOCK_DGRAM);
        if (self->sfd < 0) {
            free(self->hsbuff);
            free(self);
            return NULL;
        }
        self->phase = PHASE_FORWARDING;

        skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                      EPOLLOUT | EPOLLIN, EVUPD);
    } else {
        if ((self->hsbuff = buff_calloc(SOCKS_HS_BUFF)) == NULL)
            oom();

        /* connect to proxy server */
        self->sfd = skutils_connect(&self->info, conf->proxysrv,
                                    conf->proxyport, socktype);
        if (self->sfd < 0) {
            free(self->hsbuff);
            free(self);
            return NULL;
        }

        /* wait to handshake */
        self->phase = PHASE_SEND_METHOD;
        skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                      EPOLLOUT, EVUPD);
    }

    return self;
}

/* create a tcp connection
   this connection is proxied via socks server */
struct proxy *socks_tcp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *ip, uint16_t port)
{
    struct proxy_socks *self =
        socks_create_impl(loop, userev, userp, TCP_FORWARD, ip, port, NULL);
    return self ? &self->ops : NULL;
}

/* create a associate connection for udp forward */
struct proxy *socks_assoc_create(struct loopctx *loop, userev_fn_t *userev,
                                 void *userp)
{
    struct proxy_socks *self =
        socks_create_impl(loop, userev, userp, UDP_ASSOCIATE, "0.0.0.0", 0, NULL);
    return self ? &self->ops : NULL;
}

/* create a udp connection
   this connection is proxied via socks server */
struct proxy *socks_udp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *ip, uint16_t port,
                               struct proxy *assoc)
{
    struct proxy_socks *self;
    struct proxy_socks *as = container_of(assoc, struct proxy_socks, ops);

    if (as->phase != PHASE_FORWARDING || as->relay == NULL)
        return NULL;

    self = socks_create_impl(loop, userev, userp, UDP_FORWARD, ip, port, as);

    return self ? &self->ops : NULL;
}

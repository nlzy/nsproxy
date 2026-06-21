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
#include "core.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip6_frag.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#include "direct.h"
#include "http.h"
#include "socks.h"
#include "tcpdns.h"

/* forward between a TCP 4-tuple and a proxy connection */
struct tcp_forward {
    struct corectx *core;
    struct tcp_forward *prev;
    struct tcp_forward *next;
    struct proxy *proxy;
    struct tcp_pcb *pcb;
    struct pbuf *sndq; /* explicit TX RX queues require by lwIP */
    struct pbuf *rcvq;
    int gc;
    uint8_t proxyeof;
    uint8_t lwipeof;
};

/* forward between a UDP 4-tuple and a proxy connection */
struct udp_forward {
    struct corectx *core;
    struct udp_forward *prev;
    struct udp_forward *next;
    struct proxy *proxy;
    struct udp_pcb *pcb;
    struct pbuf *rcvq[8]; /* mitigate DNS re-trans during assoc for UX */
    int nrcvq;
    int gc;
};

/* only one context during the whole lifecycle of a process */
struct corectx {
    struct netif tunif;

    struct loopctx *loop;

    int tunfd;
    struct epcb_ops tunepcb;

    int timerfd;
    uint64_t timerepoch;
    struct epcb_ops timerepcb;

    /* tracking all living forward instances */
    struct tcp_forward *tcplst;
    struct udp_forward *udplst;

    /* a single associate connection for all udp_forward */
    struct proxy *udpassoc;
    int assocretries;
    int assoccd;
    uint8_t assocready;
};

static int is_gateway(const struct netif *netif, const ip_addr_t *addr)
{
    return ip_addr_cmp(addr, netif_ip_addr4(netif))
           || ip_addr_cmp(addr, netif_ip_addr6(netif, 0));
}

/* read packets from TUN, push to lwIP stack */
static void tun_input(struct corectx *core)
{
    struct netif *tunif = &core->tunif;
    struct pbuf *p = NULL;
    size_t budget = 250; /* avoid starve, defaults to half of TUN queue size */

    for (; budget > 0; budget--) {
        ssize_t nread;

        if ((p = pbuf_alloc(PBUF_RAW, NSPROXY_MTU, PBUF_RAM)) == NULL)
            oom();

        nread = read(core->tunfd, p->payload, p->len);
        if (nread == -1 && errno == EAGAIN) {
            break;
        } else if (nread == -1) {
            logwarn("tun_input: read tunfd failed: %s", strerror(errno));
            break;
        }

        loginfo("tun_input: read %zd bytes from TUN", nread);

        /* shrink, set p->tot_len = nread */
        pbuf_realloc(p, nread);

        if (tunif->input(p, tunif) != ERR_OK) {
            LWIP_DEBUGF(NETIF_DEBUG, ("tun_input: netif input error\n"));
            break;
        }

        p = NULL; /* ownship was moved to tunif */
    }

    if (p)
        pbuf_free(p);
}

/* write packet to TUN */
static err_t tun_output(struct corectx *core, struct pbuf *p)
{
    struct pbuf *seg;
    struct iovec iov[16];
    size_t i, clen;
    ssize_t nwrite;

    clen = pbuf_clen(p);

    if (clen > arraysizeof(iov) || p->tot_len > NSPROXY_MTU) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: packet too large\n"));
        return ERR_IF;
    }

    /* iov = segments in pbuf */
    for (seg = p, i = 0; i < clen; i++) {
        iov[i].iov_base = seg->payload;
        iov[i].iov_len = seg->len;
        seg = seg->next;
    }

    nwrite = writev(core->tunfd, iov, clen);
    if (nwrite == -1 && errno == EAGAIN) {
        /* ERR_OK is same as frame dropped at link-layer. This is fine since TUN
           almost never returns EAGAIN with default settings */
        logwarn("tun_output: tunfd EAGAIN");
        return ERR_OK;
    } else if (nwrite == -1) {
        logwarn("tun_output: writev tunfd failed: %s", strerror(errno));
        return ERR_IF;
    } else if (nwrite != p->tot_len) {
        /* should not happen, we have checked p->tot_len <= MTU */
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: partial write\n"));
        return ERR_IF;
    }

    loginfo("tun_output: wrote %zd bytes to TUN", nwrite);

    return ERR_OK;
}

static err_t tunip4_output(struct netif *netif, struct pbuf *p,
                           const ip4_addr_t *ipaddr)
{
    struct corectx *core = netif->state;
    return tun_output(core, p);
}

static err_t tunip6_output(struct netif *netif, struct pbuf *p,
                           const ip6_addr_t *ipaddr)
{
    struct corectx *core = netif->state;
    return tun_output(core, p);
}

static err_t tunlink_output(struct netif *tunif, struct pbuf *packet)
{
    logwarn("tunlink_output: netif->linkoutput called unexpectedly, drop.");
    return ERR_IF;
}

static err_t tunif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'u';

    netif->output = tunip4_output;
    netif->output_ip6 = tunip6_output;
    netif->linkoutput = tunlink_output;
    netif->mtu = NSPROXY_MTU;

    return ERR_OK;
}

static void core_tunfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, tunepcb);
    tun_input(core);
}

/* Create a new udp_forward instance and add to list */
static struct udp_forward *udp_forward_create(struct corectx *core)
{
    struct udp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL)
        oom();

    fwd->core = core;
    fwd->gc = NSPROXY_UDP_IDLE_TIMEOUT;

    /* add to head */
    fwd->next = core->udplst;
    if (core->udplst != NULL) {
        core->udplst->prev = fwd;
    }
    core->udplst = fwd;

    return fwd;
}

/* Destroy a udp_forward instance and remove from list */
static void udp_forward_destroy(struct udp_forward *fwd)
{
    struct corectx *core = fwd->core;

    /* remove from linked-list */
    if (fwd->prev != NULL) {
        fwd->prev->next = fwd->next;
    } else {
        core->udplst = fwd->next;
    }
    if (fwd->next != NULL) {
        fwd->next->prev = fwd->prev;
    }

    /* free receive queue */
    while (fwd->nrcvq --> 0) /* out of tricks, it's time to bite a lighter */
        pbuf_free(fwd->rcvq[fwd->nrcvq]);

    if (fwd->pcb) {
        udp_recv(fwd->pcb, NULL, NULL);
        udp_remove(fwd->pcb);
    }

    if (fwd->proxy)
        proxy_put(fwd->proxy);

    free(fwd);
}

/* Try to recv data from proxy server and send to application
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t udp_proxy_input(struct udp_forward *fwd)
{
    struct proxy *proxy = fwd->proxy;
    struct udp_pcb *pcb = fwd->pcb;
    char *buffer;
    struct pbuf *p = NULL;
    err_t ret;

    fwd->gc = fwd->pcb->local_port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                                         : NSPROXY_UDP_IDLE_TIMEOUT;

    if ((buffer = malloc(UDP_PACKET_MAXLEN)) == NULL)
        oom();

    for (;;) {
        err_t err;
        ssize_t nread;

        p = pbuf_alloc_reference(buffer, UDP_PACKET_MAXLEN, PBUF_REF);
        if (p == NULL)
            oom();

        nread = proxy_recv(proxy, p->payload, p->len);
        if (nread == -EAGAIN) {
            proxy_evctl(proxy, EPOLLIN, EVSET);
            ret = ERR_OK;
            break;
        } else if (nread < 0) {
            logwarn("udp_proxy_input: proxy error, destroy fwd, reason: %s",
                    strerror(-nread));
            udp_forward_destroy(fwd);
            ret = ERR_ABRT;
            break;
        }

        pbuf_realloc(p, nread); /* set p->tot_len = nread */
        err = udp_send(pcb, p);
        if (err != ERR_OK && err != ERR_MEM) {
            logwarn("udp_proxy_input: udp_send() failed, destroy fwd");
            udp_forward_destroy(fwd);
            ret = ERR_ABRT;
            break;
        }
        /* ERR_MEM: TX queue full, ignore and drop */

        /* tun_output() is synchronous, reuse pbuf is possile, but we follow
           lwIP API semantics: call pbuf_free() immediately after udp_send().
           But recycle buffer is safe, PBUF_REF is volatile and lwIP will copy
           data if they need. */
        pbuf_free(p);
        p = NULL;
    }

    if (p)
        pbuf_free(p);
    free(buffer);

    return ret;
}

/* Try to send data to proxy server, data already in fwd->rcvq
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t udp_proxy_output(struct udp_forward *fwd)
{
    struct proxy *proxy = fwd->proxy;
    ssize_t i, nsent;
    struct pbuf *p;
    char *heapbuff = NULL;

    fwd->gc = fwd->pcb->local_port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                                         : NSPROXY_UDP_IDLE_TIMEOUT;

    /* send all */
    for (i = 0; i < fwd->nrcvq; i++) {
        p = fwd->rcvq[i];
        if (p->len == p->tot_len) {
            /* only single pbuf in chain */
            nsent = proxy_send(proxy, p->payload, p->tot_len);
        } else {
            char stkbuff[2048];
            if (p->tot_len <= sizeof(stkbuff)) {
                /* prefer use stack buffer */
                pbuf_copy_partial(p, stkbuff, p->tot_len, 0);
                nsent = proxy_send(proxy, stkbuff, p->tot_len);
            } else {
                if (heapbuff == NULL) {
                    if ((heapbuff = malloc(UDP_PACKET_MAXLEN)) == NULL)
                        oom();
                }
                pbuf_copy_partial(p, heapbuff, p->tot_len, 0);
                nsent = proxy_send(proxy, heapbuff, p->tot_len);
            }
        }
        /* EAGAIN is not fatal error, and will not handle in UDP, ignore */
        if (nsent < 0 && nsent != -EAGAIN) {
            logwarn("udp_proxy_output: proxy error, force destroy fwd, "
                    "reason: %s", strerror(-nsent));
            goto failed_abort;
        }
        /* don't pbuf_free(p) here, if some packet sent succeed and some failed,
           it will leave a half-free'ed rcvq. */
    }

    for (i = 0; i < fwd->nrcvq; i++)
        pbuf_free(fwd->rcvq[i]);
    fwd->nrcvq = 0;

    /* rcvq drained */
    proxy_evctl(proxy, EPOLLOUT, EVCLR);

    free(heapbuff);
    return ERR_OK;

failed_abort:
    udp_forward_destroy(fwd);
    free(heapbuff);
    return ERR_ABRT;
}

/* called by lwip when data has received from application,
   this function push the received data to receive queue
*/
static void udp_lwip_received(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port)
{
    struct udp_forward *fwd = arg;

    if (!p) { /* should not happen */
        udp_forward_destroy(fwd);
        return;
    }

    if (fwd->nrcvq == arraysizeof(fwd->rcvq)) {
        /* receive queue full, drop oldest data in queue and enqueue this */
        pbuf_free(fwd->rcvq[0]);
        memmove(fwd->rcvq, fwd->rcvq + 1,
                (arraysizeof(fwd->rcvq) - 1) * sizeof(fwd->rcvq[0]));
        fwd->rcvq[arraysizeof(fwd->rcvq) - 1] = p;
    } else {
        fwd->rcvq[fwd->nrcvq++] = p;
    }

    if (fwd->proxy)
        udp_proxy_output(fwd);
}

/* handle event occured in connection connected to proxy server */
static void udp_proxy_io_event(void *userp, unsigned int events)
{
    struct udp_forward *fwd = userp;
    err_t err = ERR_OK;

    if (!err && (events & EPOLLIN))
        err = udp_proxy_input(fwd);

    if (!err && (events & EPOLLOUT))
        err = udp_proxy_output(fwd);

    if (!err && (events & EPOLLERR))
        udp_forward_destroy(fwd);
}

/* called by lwip when a udp connection is create
   this function create a connection to proxy server and set lwip udp_recv() up
*/
err_t core_udp_new(struct udp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct udp_forward *fwd;
    char local_ip[IPADDR_STRLEN_MAX + 1];
    char remote_ip[IPADDR_STRLEN_MAX + 1];
    char *ip;
    uint16_t port;

    ipaddr_ntoa_r(&pcb->local_ip, local_ip, sizeof(local_ip));
    ipaddr_ntoa_r(&pcb->remote_ip, remote_ip, sizeof(remote_ip));

    loginfo("core_udp_new: new struct udp_pcb: %s:%u <- %s:%u", local_ip,
            (unsigned)pcb->local_port, remote_ip, (unsigned)pcb->remote_port);

    ip = local_ip;
    port = pcb->local_port;

    fwd = udp_forward_create(core);
    fwd->pcb = pcb;
    fwd->gc = port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                         : NSPROXY_UDP_IDLE_TIMEOUT;

    udp_recv(pcb, udp_lwip_received, fwd);

    if (is_gateway(&core->tunif, &pcb->local_ip)) {
        if (port == 53 && conf->dnstype != DNS_REDIR_OFF) {
            if (conf->dnstype == DNS_REDIR_TCP) {
                fwd->proxy = tcpdns_create(core->loop, &udp_proxy_io_event, fwd);
                goto end;
            } else {
                assert(conf->dnstype == DNS_REDIR_UDP);
                ip = conf->dnssrv;
                port = conf->dnsport;
                /* DNAT to DNS server, continue */
            }
        } else {
            /* forward gateway to host namespace */
            ip = IP_IS_V4(&pcb->local_ip) ? "127.0.0.1" : "::1";
            fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd,
                                           ip, port);
            goto end;
        }
    }

    if (conf->proxytype == PROXY_SOCKS5 && !core->assocready) {
        /* leave a pending fwd */
        fwd->proxy = NULL;
        return ERR_OK;
    } else if (conf->proxytype == PROXY_SOCKS5) {
        fwd->proxy = socks_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                      port, core->udpassoc);
    } else if (conf->proxytype == PROXY_DIRECT) {
        fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                       port);
    }

end:
    if (fwd->proxy == NULL) {
        udp_forward_destroy(fwd);
        return ERR_ABRT; /* can't handle, return ERR_ABRT to send ICMP unreach */
    } else {
        return ERR_OK;
    }
}

/* handle events in in struct proxy, for UDP associate connection */
static void udp_assoc_io_event(void *userp, unsigned int events)
{
    struct corectx *core = userp;
    struct udp_forward *fwd;

    /* unexpected events on udpassoc connection, clean up and set countdown */
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
        int cdexp = core->assocretries <= 5 ? core->assocretries : 5;

        proxy_put(core->udpassoc);
        core->udpassoc = NULL;
        core->assocready = 0;
        core->assoccd = 1 << cdexp; /* exponent backoff */

        return;
    }

    /* interest on EPOLLOUT only once, so now assoc just succeed */
    proxy_evctl(core->udpassoc, EPOLLOUT, EVCLR);
    core->assocready = 1;
    core->assocretries = 0;

    /* connect to proxy for pending fwd */
    for (fwd = core->udplst; fwd;) {
        struct udp_pcb *pcb = fwd->pcb;
        char ip[IPADDR_STRLEN_MAX + 1];

        if (fwd->proxy) { /* not pending */
            fwd = fwd->next;
            continue;
        }

        ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
        fwd->proxy = socks_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                      pcb->local_port, core->udpassoc);
        if (fwd->proxy == NULL) {
            struct udp_forward *next = fwd->next; /* save next in linked-list */
            udp_forward_destroy(fwd);
            fwd = next;
            continue;
        }

        fwd = fwd->next;
    }
}

/* Create a new tcp_forward instance and add to list */
static struct tcp_forward *tcp_forward_create(struct corectx *core)
{
    struct tcp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL)
        oom();

    fwd->core = core;
    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    /* add to head */
    fwd->next = core->tcplst;
    if (core->tcplst != NULL) {
        core->tcplst->prev = fwd;
    }
    core->tcplst = fwd;

    return fwd;
}

/* Destroy a tcp_forward instance and remove from list */
static void tcp_forward_destroy(struct tcp_forward *fwd, int force)
{
    struct corectx *core = fwd->core;
    int rst = 0;

    /* queues not drained, breaks TCP reliable delivery semantics, RST */
    if (fwd->sndq != NULL || fwd->rcvq != NULL)
        rst = 1;

    /* remove from linked-list */
    if (fwd->prev != NULL)
        fwd->prev->next = fwd->next;
    else
        core->tcplst = fwd->next;
    if (fwd->next != NULL)
        fwd->next->prev = fwd->prev;

    if (fwd->pcb) {
        /* avoid tcp_close() calls callbacks again on destroy path */
        tcp_arg(fwd->pcb, NULL);
        tcp_sent(fwd->pcb, NULL);
        tcp_recv(fwd->pcb, NULL);
        tcp_err(fwd->pcb, NULL);
        if (force || rst) {
            tcp_abort(fwd->pcb);
        } else {
            if (tcp_close(fwd->pcb) != ERR_OK)
                tcp_abort(fwd->pcb); /* tcp_close() may failed, abort it. */
        }
    }

    if (fwd->proxy) {
        if (force || rst)
            proxy_shutdown(fwd->proxy, SHUT_RDWR, 1);
        proxy_put(fwd->proxy);
    }

    if (fwd->sndq)
        pbuf_free(fwd->sndq);
    if (fwd->rcvq)
        pbuf_free(fwd->rcvq);

    free(fwd);
}

/* Try to recv data from proxy server and send to application
   May called from lwip context if
   - data are ack'ed by lwip
   May called from epoll context if
   - data are received from proxy server, in socket buffer
   - EOF is received from proxy server
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t tcp_proxy_input(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct proxy *proxy = fwd->proxy;
    struct pbuf *p;

    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (!fwd->proxyeof && tcp_sndbuf(pcb) > tcp_mss(pcb)
           && tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2) {
        ssize_t nread;

        if ((p = pbuf_alloc(PBUF_RAW, tcp_mss(pcb), PBUF_RAM)) == NULL)
            oom();

        nread = proxy_recv(proxy, p->payload, p->len);
        if (nread == -EAGAIN) {
            proxy_evctl(proxy, EPOLLIN, EVSET);
            pbuf_free(p);
            return ERR_OK;
        } else if (nread < 0) {
            logwarn("tcp_proxy_input: proxy error, force destroy fwd "
                    "reason: %s", strerror(-nread));
            goto failed_after_pbuf_alloc;
        } else if (nread == 0) {
            loginfo("tcp_proxy_input: received EOF from proxy");
            fwd->proxyeof = 1;
            pbuf_free(p);
            break;
        } else {
            pbuf_realloc(p, nread); /* set to actual length */

            /* send and leave data stay in sndq, free after ACK */
            if (tcp_write(pcb, p->payload, nread, 0) != ERR_OK) {
                logwarn("tcp_proxy_input: tcp_write() failed");
                goto failed_after_pbuf_alloc;
            }
            if (fwd->sndq == NULL)
                fwd->sndq = p;
            else
                pbuf_cat(fwd->sndq, p);

            /* Typically tcp_write() + tcp_output() calling sequence.
               Failures are ignored since tcp_tmr() will auto retry as long as
               data was enqueued by tcp_write() */
            tcp_output(pcb);
        }
    }

    /* no space in sndq available or proxy EOF, stop polling EPOLLIN */
    proxy_evctl(proxy, EPOLLIN, EVCLR);

    /* received EOF from proxy, and all datas has been sent to lwip,
       forward this EOF to lwip now */
    if (fwd->proxyeof && !fwd->sndq) {
        loginfo("tcp_proxy_input: sndq drained, half-closing lwip");
        tcp_shutdown(pcb, 0, 1);
        if (fwd->lwipeof && !fwd->rcvq) {
            loginfo("tcp_proxy_input: full-closing");
            tcp_forward_destroy(fwd, 0);
            return ERR_CLSD;
        }
    }

    return ERR_OK;

failed_after_pbuf_alloc:
    pbuf_free(p);
    tcp_forward_destroy(fwd, 1);
    return ERR_ABRT;
}

/* Try to send data to proxy server
   Called from lwip context if
   - data are received from lwip, in fwd->rcvq
   - EOF is received from lwip
   Called from epoll context if:
   - there is some free space available in socket buffer
   If return value is not ERR_OK, fwd was free'ed, caller should not continue
*/
static err_t tcp_proxy_output(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct proxy *proxy = fwd->proxy;
    ssize_t nsent;

    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (fwd->rcvq) {
        nsent = proxy_send(proxy, fwd->rcvq->payload, fwd->rcvq->len);
        if (nsent == -EAGAIN) {
            proxy_evctl(proxy, EPOLLOUT, EVSET);
            return ERR_OK;
        } else if (nsent < 0) {
            logwarn("tcp_proxy_output: proxy error, force destroy fwd, "
                    "reason: %s", strerror(-nsent));
            tcp_forward_destroy(fwd, 1);
            return ERR_ABRT;
        } else {
            fwd->rcvq = pbuf_free_header(fwd->rcvq, nsent);
            tcp_recved(pcb, nsent);
        }
    }

    /* rcvq drained */
    proxy_evctl(proxy, EPOLLOUT, EVCLR);

    /* received EOF from lwip, and all datas has been sent to proxy,
       forward this EOF to proxy now */
    if (fwd->lwipeof) {
        loginfo("tcp_proxy_output: rcvq drained, half-closing proxy");
        proxy_shutdown(proxy, SHUT_WR, 0);
        /* full close */
        if (fwd->proxyeof && !fwd->sndq) {
            loginfo("tcp_proxy_output: full-closing");
            tcp_forward_destroy(fwd, 0);
            return ERR_CLSD;
        }
    }

    return ERR_OK;
}

/* called by lwip when application acked data,
   this function free sending queue, and ask more data from proxy server
*/
static err_t tcp_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct tcp_forward *fwd = arg;

    /* remove ack'ed data from send queue */
    fwd->sndq = pbuf_free_header(fwd->sndq, len);

    /* ask proxy server for more data, if we have space in queue */
    if (tcp_sndbuf(pcb) >= TCPWND16(TCP_SND_BUF / 2))
        if (tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2)
            return tcp_proxy_input(fwd);

    return ERR_OK;
}

/* called by lwip when data has received from application,
   this function push the these data to receive queue
*/
static err_t tcp_lwip_received(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err)
{
    struct tcp_forward *fwd = arg;

    if (p) {
        /* here's some data need enqueue, rcvq should not full */
        if (fwd->rcvq)
            pbuf_cat(fwd->rcvq, p);
        else
            fwd->rcvq = p;
    } else {
        loginfo("tcp_lwip_received: received EOF from lwip");
        fwd->lwipeof = 1;
    }

    if (!err)
        tcp_ack_now(pcb); /* lwIP delayed ACK (up to 250ms) is slow for TUN */

    return tcp_proxy_output(fwd);
}

/* called by lwip when TCP connection has been destroyed,
   just destroy tcp_forward but remember that PCB has been gone
*/
static void tcp_lwip_err(void *arg, err_t err)
{
    struct tcp_forward *fwd = arg;
    if (fwd) {
        logwarn("tcp_lwip_err: lwip error, force destroy fwd");
        fwd->pcb = NULL;
        tcp_forward_destroy(fwd, 1);
    }
}

/* handle events occured in connection connected to proxy server */
static void tcp_proxy_io_event(void *userp, unsigned int events)
{
    struct tcp_forward *fwd = userp;
    err_t err = ERR_OK;

    /* There's may some confuse that we don't care EPOLLERR here. We add fd to
       epoll instance iff we are interested in either EPOLLIN or EPOLLOUT, which
       is always return together with EPOLLERR if socket error. (see select(2)).
       That's means socket error will be handled in tcp_proxy_{input|output}
       Ignore EPOLLERR here not only for reduce codes in error path, but also
       avoid data lost if proxy sent DATA+RST */
    if (events & EPOLLERR)
        assert(events & (EPOLLIN | EPOLLOUT)); /* note that fact to you */

    if (!err && (events & EPOLLIN))
        err = tcp_proxy_input(fwd);

    if (!err && (events & EPOLLOUT))
        err = tcp_proxy_output(fwd);

    if (!err && !fwd->pcb->proxyestab) {
        /* SYN+ACK is delayed until proxy established, send it now */
        fwd->pcb->proxyestab = 1;
        tcp_output(fwd->pcb);
    }
}

/* called by lwip when a tcp connection is create
   this function create a connection to proxy server and set lwip tcp_*() up
*/
err_t core_tcp_new(struct tcp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct tcp_forward *fwd;
    char local_ip[IPADDR_STRLEN_MAX + 1];
    char remote_ip[IPADDR_STRLEN_MAX + 1];
    char *ip;
    uint16_t port;

    ipaddr_ntoa_r(&pcb->local_ip, local_ip, sizeof(local_ip));
    ipaddr_ntoa_r(&pcb->remote_ip, remote_ip, sizeof(remote_ip));

    loginfo("core_tcp_new: new struct tcp_pcb: %s:%u <- %s:%u", local_ip,
            (unsigned)pcb->local_port, remote_ip, (unsigned)pcb->remote_port);

    ip = local_ip;
    port = pcb->local_port;

    fwd = tcp_forward_create(core);
    fwd->pcb = pcb;

    tcp_nagle_disable(pcb);
    tcp_arg(pcb, fwd);
    tcp_sent(pcb, &tcp_lwip_sent);
    tcp_recv(pcb, &tcp_lwip_received);
    tcp_err(pcb, &tcp_lwip_err);

    if (is_gateway(&core->tunif, &pcb->local_ip)) {
        /* forward gateway to host namespace  */
        ip = IP_IS_V4(&pcb->local_ip) ? "127.0.0.1" : "::1";
        fwd->proxy =
            direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip, port);
        goto end;
    }

    if (conf->proxytype == PROXY_SOCKS5) {
        fwd->proxy =
            socks_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip, port);
    } else if (conf->proxytype == PROXY_HTTP) {
        fwd->proxy =
            http_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip, port);
    } else {
        fwd->proxy =
            direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip, port);
    }

end:
    if (fwd->proxy == NULL) {
        tcp_forward_destroy(fwd, 1);
        return ERR_ABRT;
    } else {
        return ERR_OK;
    }
}

/* call every 1s */
static void core_gc_tmr(struct corectx *core)
{
    struct tcp_forward *tcur = core->tcplst;
    struct udp_forward *ucur = core->udplst;

    while (tcur) {
        struct tcp_forward *next = tcur->next;
        if (tcur->gc-- == 0)
            tcp_forward_destroy(tcur, 1);
        tcur = next;
    }

    while (ucur) {
        struct udp_forward *next = ucur->next;
        if (ucur->gc-- == 0)
            udp_forward_destroy(ucur);
        ucur = next;
    }
}

/* call every 1s */
static void core_reassoc_tmr(struct corectx *core)
{
    struct loopctx *loop = core->loop;

    if (current_nspconf()->proxytype != PROXY_SOCKS5)
        return;

    if (core->udpassoc == NULL && !core->assocready) {
        /* re-associate is needed */
        if (core->assoccd > 0) {
            /* exponent backoff countdown */
            core->assoccd--;
        } else {
            /* re-associate */
            core->udpassoc = socks_assoc_create(loop, &udp_assoc_io_event, core);
            core->assocretries++;
        }
    }
}

/* call every 250ms */
static void core_timerfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, timerepcb);
    uint64_t expired;

    if (read(core->timerfd, &expired, sizeof(expired)) == -1) {
        logwarn("core_timerfd_epcb_events: read timerfd failed: %s",
                strerror(errno));
        return;
    }
    /* no wall clock in submodules, use while-loop to feed all expired ticks */
    while (expired--) {
        if (core->timerepoch % 4 == 0) {
            core_gc_tmr(core);
            core_reassoc_tmr(core);
            ip_reass_tmr();
            ip6_reass_tmr();
            nd6_tmr();
        }
        tcp_tmr();
        core->timerepoch++;
    }
}

int core_init(struct corectx **core, struct loopctx *loop, int tunfd)
{
    struct corectx *p;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;
    ip6_addr_t tunaddr6;
    struct itimerspec its = { .it_interval.tv_nsec = 250000000,
                              .it_value.tv_nsec = 250000000 };

    if ((p = calloc(1, sizeof(struct corectx))) == NULL)
        oom();

    p->tunfd = tunfd;
    p->loop = loop;

    /* lwip required call to some functions periodically every 250ms */
    if ((p->timerfd = timerfd_create(CLOCK_MONOTONIC,
                                     TFD_NONBLOCK | TFD_CLOEXEC)) == -1) {
        loglv0("core_init: timerfd_create() failed: %s", strerror(errno));
        goto failed_after_malloc;
    }
    if ((timerfd_settime(p->timerfd, 0, &its, NULL)) == -1) {
        loglv0("core_init: timerfd_settime() failed: %s", strerror(errno));
        goto failed_after_timerfd_create;
    }

    /* register tunfd to epoll */
    p->tunepcb.on_epoll_events = &core_tunfd_epcb_events;
    if (loop_epoll_ctl(loop, EPOLL_CTL_ADD, tunfd, EPOLLIN, &p->tunepcb) < 0)
        goto failed_after_timerfd_create;

    /* register timerfd to epoll */
    p->timerepcb.on_epoll_events = &core_timerfd_epcb_events;
    if (loop_epoll_ctl(loop, EPOLL_CTL_ADD, p->timerfd, EPOLLIN,
                       &p->timerepcb) < 0)
        goto failed_after_timerfd_create;

    lwip_init();
    ip4addr_aton(NSPROXY_GATEWAY_IP, &tunaddr);
    ip4addr_aton(NSPROXY_NETMASK, &tunnetmask);
    ip4addr_aton("0.0.0.0", &tungateway);

    netif_add(&p->tunif, &tunaddr, &tunnetmask, &tungateway, p, &tunif_init,
              &ip_input);
    netif_set_default(&p->tunif);
    netif_set_link_up(&p->tunif);
    netif_set_up(&p->tunif);

    if (current_nspconf()->ipv6) {
        ip6addr_aton(NSPROXY_GATEWAY_IPV6, &tunaddr6);
        netif_ip6_addr_set(&p->tunif, 0, &tunaddr6);
        netif_ip6_addr_set_state(&p->tunif, 0, IP6_ADDR_PREFERRED);
    }

    loginfo("core_init: initialized lwIP core forwarding module (corectx)");

    if (current_nspconf()->proxytype == PROXY_SOCKS5) {
        p->udpassoc = socks_assoc_create(loop, &udp_assoc_io_event, p);
        p->assocready = 0;
    } else if (current_nspconf()->proxytype == PROXY_DIRECT) {
        p->udpassoc = NULL;
        p->assocready = 1;
    } else {
        p->udpassoc = NULL;
        p->assocready = 0;
    }
    p->assocretries = 0;
    p->assoccd = 0;

    *core = p;
    return 0;

failed_after_timerfd_create:
    close(p->timerfd);
failed_after_malloc:
    free(p);
    return -1;
}

void core_deinit(struct corectx *core)
{
    while (core->tcplst)
        tcp_forward_destroy(core->tcplst, 1);
    while (core->udplst)
        udp_forward_destroy(core->udplst);

    if (core->udpassoc)
        proxy_put(core->udpassoc);

    netif_remove(&core->tunif);

    if (close(core->timerfd))
        loglv0("core_deinit: timerfd close() failed: %s", strerror(errno));

    free(core);
}

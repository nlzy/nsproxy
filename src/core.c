#include "core.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip6_addr.h"

#include "direct.h"
#include "dns.h"
#include "http.h"
#include "socks.h"

struct tcp_forward {
    struct corectx *core;
    struct tcp_forward *prev;
    struct tcp_forward *next;
    struct sk_ops *proxy;
    struct tcp_pcb *pcb;
    struct pbuf *sndq;
    struct pbuf *rcvq;
    unsigned int gc;
    u8_t proxyeof;
    u8_t lwipeof;
};

struct udp_forward {
    struct corectx *core;
    struct udp_forward *prev;
    struct udp_forward *next;
    struct sk_ops *proxy;
    struct udp_pcb *pcb;
    struct pbuf *rcvq[8];
    unsigned int gc;
    u16_t nrcvq;
};

struct corectx {
    struct netif tunif;

    struct loopctx *loop;

    int tunfd;
    struct epcb_ops tunepcb;

    int timerfd;
    uint64_t timerepoch;
    struct epcb_ops timerepcb;

    /* tracking all forward instances */
    struct tcp_forward *tcplst;
    struct udp_forward *udplst;
};

static void tun_input(struct netif *tunif)
{
    struct corectx *core = tunif->state;
    ssize_t nread;
    struct pbuf *p;

    if ((p = pbuf_alloc(PBUF_RAW, NSPROXY_MTU, PBUF_RAM)) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    if ((nread = read(core->tunfd, p->payload, p->len)) == -1) {
        perror("read()");
        abort();
    }

    /* shirk, set p->tot_len = nread */
    pbuf_realloc(p, nread);

    loglv(3, "tun_input: read %zd bytes from TUN", nread);

    if (tunif->input(p, tunif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_input: netif input error\n"));
        pbuf_free(p);
    }
}

static err_t tun_output(struct netif *tunif, struct pbuf *p)
{
    struct corectx *core = tunif->state;
    struct pbuf *orig = p;
    struct iovec iov[16];
    size_t n = 0;
    ssize_t nwrite;

    if (p->tot_len > NSPROXY_MTU) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: packet too large\n"));
        return ERR_IF;
    }

    while (n != arraysizeof(iov)) {
        iov[n].iov_base = p->payload;
        iov[n].iov_len = p->len;
        n++;
        /* lwip used below as loop end condiction, not p->next == NULL */
        if (p->len == p->tot_len)
            break;
        else
            p = p->next;
    }
    if ((nwrite = writev(core->tunfd, iov, n)) == -1) {
        perror("write()");
        abort();
    }
    if (nwrite != orig->tot_len) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: partial write\n"));
        return ERR_IF;
    }

    loglv(3, "tun_output: wrote %zd bytes to TUN", nwrite);

    return ERR_OK;
}

static err_t tunip4_output(struct netif *netif, struct pbuf *p,
                           const ip4_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

static err_t tunip6_output(struct netif *netif, struct pbuf *p,
                           const ip6_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

static err_t tunif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'u';

    netif->output = tunip4_output;
    netif->output_ip6 = tunip6_output;
    netif->linkoutput = tun_output;
    netif->mtu = NSPROXY_MTU;

    return ERR_OK;
}


/* Create a new tcp_forward instance and add to list */
static struct tcp_forward *tcp_forward_create(struct corectx *core)
{
    struct tcp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    fwd->core = core;
    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    /* Add to head of list */
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

    /* remove from list */
    if (fwd->prev != NULL)
        fwd->prev->next = fwd->next;
    else
        core->tcplst = fwd->next;

    if (fwd->next != NULL)
        fwd->next->prev = fwd->prev;

    /* free pcb */
    if (fwd->pcb) {
        tcp_err(fwd->pcb, NULL);
        if (force)
            tcp_abort(fwd->pcb);
        else        
            tcp_close(fwd->pcb);
    }

    /* free proxy */
    if (fwd->proxy) {
        if (force)
            fwd->proxy->shutdown(fwd->proxy, SHUT_RDWR, 1);
        fwd->proxy->put(fwd->proxy);
    }

    /* free queues */
    if (fwd->sndq)
        pbuf_free(fwd->sndq);
    if (fwd->rcvq)
        pbuf_free(fwd->rcvq);

    free(fwd);
}

/* Create a new udp_forward instance and add to list */
static struct udp_forward *udp_forward_create(struct corectx *core)
{
    struct udp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    fwd->core = core;
    fwd->gc = NSPROXY_UDP_IDLE_TIMEOUT;

    /* Add to head of list */
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

    /* remove from list */
    if (fwd->prev != NULL) {
        fwd->prev->next = fwd->next;
    } else {
        core->udplst = fwd->next;
    }
    if (fwd->next != NULL) {
        fwd->next->prev = fwd->prev;
    }

    /* free pcb */
    if (fwd->pcb)
        udp_remove(fwd->pcb);

    /* free proxy */
    if (fwd->proxy)
        fwd->proxy->put(fwd->proxy);

    /* free receive queue */
    while (fwd->nrcvq --> 0) { /* out of tricks, it's time to bite a lighter */
        pbuf_free(fwd->rcvq[fwd->nrcvq]);
    }

    free(fwd);
}

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

static void core_tunfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, tunepcb);
    tun_input(&core->tunif);
}

static void core_timerfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, timerepcb);
    uint64_t expired;

    if (read(core->timerfd, &expired, sizeof(expired)) == -1) {
        perror("read()");
        abort();
    }
    while (expired--) {
        if (core->timerepoch % 4 == 0) {
            core_gc_tmr(core);
            ip_reass_tmr();
            ip6_reass_tmr();
            nd6_tmr();
        }
        tcp_tmr();
        core->timerepoch++;
    }
}

void core_init(struct corectx **core, struct loopctx *loop, int tunfd)
{
    struct corectx *p;
    struct epoll_event ev;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;
    ip6_addr_t tunaddr6;
    struct itimerspec its = { .it_interval.tv_nsec = 250000000,
                              .it_value.tv_nsec = 250000000 };

    if ((p = calloc(1, sizeof(struct corectx))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    p->tunfd = tunfd;
    p->loop = loop;

    /* lwip required call to some functions periodically every 250ms */
    if ((p->timerfd = timerfd_create(CLOCK_MONOTONIC,
                                     TFD_NONBLOCK | TFD_CLOEXEC)) == -1) {
        perror("timerfd_create()");
        abort();
    }
    if ((timerfd_settime(p->timerfd, 0, &its, NULL)) == -1) {
        perror("timerfd_settime()");
        abort();
    }

    /* register tunfd and timerfd to epoll */
    p->tunepcb.on_epoll_events = &core_tunfd_epcb_events;
    loop_epoll_ctl(loop, EPOLL_CTL_ADD, tunfd, EPOLLIN, &p->tunepcb);
    p->timerepcb.on_epoll_events = &core_timerfd_epcb_events;
    loop_epoll_ctl(loop, EPOLL_CTL_ADD, p->timerfd, EPOLLIN, &p->timerepcb);

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

    loglv(3, "core_init: corectx and lwip initialized");

    *core = p;
}

void core_deinit(struct corectx *core)
{
    int ret;

    while (core->tcplst)
        tcp_forward_destroy(core->tcplst, 0);
    while (core->udplst)
        udp_forward_destroy(core->udplst);

    netif_remove(&core->tunif);

    if ((ret = close(core->timerfd)) == -1) {
        perror("close(core->timerfd)");
        abort();
    }
    if ((ret = close(core->tunfd)) == -1) {
        perror("close(core->tunfd)");
        abort();
    }

    free(core);
}

/* try to recv data from proxy server and send to application */
static void udp_proxy_input(struct udp_forward *fwd)
{
    struct sk_ops *proxy = fwd->proxy;
    struct udp_pcb *pcb = fwd->pcb;

    /* reset gc ttl */
    fwd->gc = fwd->pcb->local_port == 53
        ? NSPROXY_DNS_IDLE_TIMEOUT
        : NSPROXY_UDP_IDLE_TIMEOUT;

    for (;;) {
        char buffer[65535];
        ssize_t nread;
        struct pbuf *p;

        nread = proxy->recv(proxy, buffer, sizeof(buffer));

        if (nread < 0) {
            proxy->evctl(proxy, EPOLLIN, 1);
            return;
        }

        if ((p = pbuf_alloc_reference(buffer, nread, PBUF_REF)) == NULL) {
            fprintf(stderr, "Out of Memory.\n");
            abort();
        }

        if (udp_send(pcb, p) != ERR_OK) {
            fprintf(stderr, "Out of Memory.\n");
            abort();
        }

        pbuf_free(p);
    }
}

/* try to send data to proxy server, data already in fwd->rcvq */
static void udp_proxy_output(struct udp_forward *fwd)
{
    struct sk_ops *proxy = fwd->proxy;
    char buffer[65535];
    ssize_t i, nsent;
    struct pbuf *p;

    /* reset gc ttl */
    fwd->gc = fwd->pcb->local_port == 53
        ? NSPROXY_DNS_IDLE_TIMEOUT
        : NSPROXY_UDP_IDLE_TIMEOUT;

    /* send all */
    for (i = 0; i < fwd->nrcvq; i++) {
        p = fwd->rcvq[i];
        if (p->len == p->tot_len) {
            nsent = proxy->send(proxy, p->payload, p->tot_len);
        } else {
            pbuf_copy_partial(p, buffer, p->tot_len, 0);
            nsent = proxy->send(proxy, buffer, p->tot_len);
        }

        if (nsent == -EAGAIN)
            break;

        /* Succeed. Or failed other than EAGAIN which would not handled in UDP.
         */
        pbuf_free(p);
    }

    fwd->nrcvq -= i;

    if (fwd->nrcvq > 0) {
        /* EAGAIN happened at i packet*/
        memmove(fwd->rcvq, fwd->rcvq + i, fwd->nrcvq * sizeof(fwd->rcvq[0]));
        proxy->evctl(proxy, EPOLLOUT, 1);
    } else {
        proxy->evctl(proxy, EPOLLOUT, 0);
    }
}

/* handle event occured in connection connected to proxy server */
static void udp_proxy_io_event(void *userp, unsigned int event)
{
    struct udp_forward *fwd = userp;

    /* Fatal errors (e.g. ENOMEM) already handled in the impl of sk_ops.
       Other failures (e.g. ECONNABORTED) handled here, others part of this
       program could simplely retry when IO error occured.
    */
    if (event & EPOLLERR) {
        loglv(3, "udp_proxy_io_event: proxy error, force destroy fwd");
        udp_forward_destroy(fwd);
        return;
    }

    if (event & EPOLLIN) {
        udp_proxy_input(fwd);
    }

    if (event & EPOLLOUT) {
        udp_proxy_output(fwd);
    }
}

/* called by lwip when data has received from application,
   this funcion push the received data to receive queue
*/
static void udp_lwip_received(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port)
{
    struct udp_forward *fwd = arg;
    struct sk_ops *proxy = fwd->proxy;

    if (!p) {
        /* should not happen */
        udp_forward_destroy(fwd);
        return;
    }

    if (!proxy) {
        /* lost connection to proxy server,
           reply ICMP port unreach message, and release udp pcb
        */
        pbuf_header_force(p, (s16_t)(ip_current_header_tot_len() + UDP_HLEN));
        icmp_port_unreach(ip_current_is_v6(), p);
        pbuf_free(p);
        udp_forward_destroy(fwd);
        return;
    }

    if (fwd->nrcvq == arraysizeof(fwd->rcvq)) {
        /* receive queue full, drop oldest data in queue and enqueue this */
        memmove(fwd->rcvq, fwd->rcvq + 1,
                (arraysizeof(fwd->rcvq) - 1) * sizeof(fwd->rcvq[0]));
        fwd->rcvq[arraysizeof(fwd->rcvq) - 1] = p;
    } else {
        fwd->rcvq[fwd->nrcvq++] = p;
    }

    udp_proxy_output(fwd);
}

/* called by lwip when a udp connection is create
   this function create a connection to proxy server and set lwip udp_recv() up
*/
void core_udp_new(struct udp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct udp_forward *fwd;
    char *addr = ipaddr_ntoa(&pcb->local_ip);
    uint16_t port = pcb->local_port;

    fwd = udp_forward_create(core);
    fwd->pcb = pcb;
    fwd->gc = pcb->local_port == 53
        ? NSPROXY_DNS_IDLE_TIMEOUT
        : NSPROXY_UDP_IDLE_TIMEOUT;

    udp_recv(pcb, udp_lwip_received, fwd);

    /* redir for DNS */
    if (port == 53 && strcmp(addr, NSPROXY_GATEWAY_IP) == 0) {
        if (conf->dnstype == DNS_REDIR_OFF) {
            /* let udp_lwip_received() drop packet */
            fwd->proxy = NULL;
            return;
        }
        if (conf->dnstype == DNS_REDIR_TCP) {
            fwd->proxy = tcpdns_create(core->loop, &udp_proxy_io_event, fwd);
            fwd->proxy->connect(fwd->proxy, conf->dnssrv, port);
            return;
        }
        if (conf->dnstype == DNS_REDIR_UDP) {
            addr = conf->dnssrv;
            /* continue */
        }
    }

    if (conf->proxytype == PROXY_SOCKS5) {
        fwd->proxy = socks_udp_create(core->loop, &udp_proxy_io_event, fwd);
        fwd->proxy->connect(fwd->proxy, addr, port);
    } else if (conf->proxytype == PROXY_HTTP) {
        /* let udp_lwip_received() drop packet */
        fwd->proxy = NULL;
    } else {
        fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd);
        fwd->proxy->connect(fwd->proxy, addr, port);
    }
}

/* try to recv data from proxy server and send to application
   may called from lwip context if
   - data are ack'ed by lwip
   may called from epoll contest if
   - data are received from proxy server, in socket buffer
   - EOF is received from proxy server
*/
static err_t tcp_proxy_input(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct sk_ops *proxy = fwd->proxy;

    /* reset gc ttl */
    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (!fwd->proxyeof && tcp_sndbuf(pcb) > tcp_mss(pcb)
           && tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2) {
        ssize_t nread;
        struct pbuf *p;

        if ((p = pbuf_alloc(PBUF_RAW, tcp_mss(pcb), PBUF_RAM)) == NULL) {
            fprintf(stderr, "Out of Memory.\n");
            abort();
        }

        nread = proxy->recv(proxy, p->payload, p->len);
        if (nread == -EAGAIN) {
            proxy->evctl(proxy, EPOLLIN, 1);
            pbuf_free(p);
            return ERR_OK;
        } else if (nread < 0) {
            loglv(3, "tcp_proxy_input: proxy error, force destroy fwd "
                     "reason: %s", strerror(-nread));
            tcp_forward_destroy(fwd, 1);
            pbuf_free(p);
            return ERR_ABRT;
        } else if (nread == 0) {
            loglv(3, "tcp_proxy_input: received EOF from proxy");
            fwd->proxyeof = 1;
            pbuf_free(p);
        } else {
            /* set acture length for pbuf */
            pbuf_realloc(p, nread);

            /* send to application and enqueue to fwd->sndq */
            if (tcp_write(pcb, p->payload, nread, 0) != ERR_OK) {
                fprintf(stderr, "Out of Memory.\n");
                abort();
            }
            /* p is moved into fwd->sndq, don't free */
            if (fwd->sndq == NULL)
                fwd->sndq = p;
            else
                pbuf_cat(fwd->sndq, p);

            tcp_output(pcb); /* don't delay */
        } 
    }

    /* no space in sndq available or proxy EOF, stop polling EPOLLIN */
    proxy->evctl(proxy, EPOLLIN, 0);

    /* received EOF from proxy, and all datas has been sent to lwip,
       forward this EOF to lwip now */
    if (fwd->proxyeof && !fwd->sndq) {
        loglv(3, "tcp_lwip_sent: sndq drained, half-closing lwip");
        tcp_shutdown(pcb, 0, 1);
        if (fwd->lwipeof && !fwd->rcvq) {
            loglv(3, "tcp_lwip_sent: full-closing");
            tcp_forward_destroy(fwd, 0);
        }
    }

    return ERR_OK;
}

/* try to send data to proxy server
   called from lwip context if
   - data are received from lwip, in fwd->rcvq
   - EOF is reveived from lwip
   called from epoll contest if:
   - there is some free space available in socket buffer
*/
static err_t tcp_proxy_output(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct sk_ops *proxy = fwd->proxy;
    ssize_t nsent;

    /* reset gc ttl */
    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (fwd->rcvq) {
        nsent = proxy->send(proxy, fwd->rcvq->payload, fwd->rcvq->len);
        if (nsent == -EAGAIN) {
            proxy->evctl(proxy, EPOLLOUT, 1);
            return ERR_OK;
        } else if (nsent < 0) {
            loglv(3, "tcp_proxy_output: proxy error, force destroy fwd, "
                     "reason: %s", strerror(-nsent));
            tcp_forward_destroy(fwd, 1);
            return ERR_ABRT;
        } else {
            fwd->rcvq = pbuf_free_header(fwd->rcvq, nsent);
            tcp_recved(pcb, nsent);
        }
    }

    /* rcvq is now empty, stop polling EPOLLOUT */
    proxy->evctl(proxy, EPOLLOUT, 0);

    /* received EOF from lwip, and all datas has been sent to proxy,
       forward this EOF to proxy now */
    if (fwd->lwipeof) {
        loglv(3, "tcp_proxy_output: rcvq drained, half-closing proxy");
        proxy->shutdown(proxy, SHUT_WR, 0);
        /* full close */
        if (fwd->proxyeof && !fwd->sndq) {
            loglv(3, "tcp_proxy_output: full-closing"); 
            tcp_forward_destroy(fwd, 0);
        }
    }

    return ERR_OK;
}

/* handle event occured in connection connected to proxy server */
static void tcp_proxy_io_event(void *userp, unsigned int event)
{
    struct tcp_forward *fwd = userp;
    err_t err = ERR_OK;

    /* handshake with proxy server failed */
    if (event == ~0u) {
        tcp_forward_destroy(fwd, 1);
        return;
    }

    /* There's may some confuse that we don't care EPOLLERR here
       see select(2)
    */
    if (event & EPOLLERR)
        assert(event & (EPOLLIN | EPOLLOUT));

    if (!err && !fwd->pcb->proxyestab) {
        fwd->pcb->proxyestab = 1;
        err = tcp_output(fwd->pcb);
    }

    if (!err && (event & EPOLLIN))
        err = tcp_proxy_input(fwd);

    if (!err && (event & EPOLLOUT))
        err = tcp_proxy_output(fwd);
}

/* called by lwip when application acked data,
   this funcion free sending queue, and ask more data from proxy server
*/
static err_t tcp_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct tcp_forward *fwd = arg;

    /* remove ackeded data from send queue */
    fwd->sndq = pbuf_free_header(fwd->sndq, len);

    /* ask proxy server for more data, if we have space in queue */
    if (tcp_sndbuf(pcb) >= TCPWND16(TCP_SND_BUF / 2))
        if (tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2)
                return tcp_proxy_input(fwd);

    return ERR_OK;
}

/* called by lwip when data has received from application,
   this funcion push the these data to receive queue
*/
static err_t tcp_lwip_received(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err)
{
    struct tcp_forward *fwd = arg;
    err_t ret;

    if (p) {
        /* here's some data need enqueue, rcvq should not full */
        if (fwd->rcvq)
            pbuf_cat(fwd->rcvq, p);
        else
            fwd->rcvq = p;
    } else {
        loglv(3, "tcp_lwip_received: received EOF from lwip");
        fwd->lwipeof = 1;
    }

    ret = tcp_proxy_output(fwd);

    if (ret == ERR_OK)
        tcp_ack(pcb); /* ack immediately */

    return ret;
}

static void tcp_lwip_err(void *arg, err_t err)
{
    struct tcp_forward *fwd = arg;
    if (fwd) {
        loglv(3, "tcp_lwip_err: lwip error, force destroy fwd");
        fwd->pcb= NULL;
        tcp_forward_destroy(fwd, 1);
    }
}

/* called by lwip when a tcp connection is create
   this function create a connection to proxy server and set lwip tcp_*() up
*/
void core_tcp_new(struct tcp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct tcp_forward *fwd;

    fwd = tcp_forward_create(core);
    fwd->pcb = pcb;

    tcp_nagle_disable(pcb);
    tcp_arg(pcb, fwd);
    tcp_sent(pcb, &tcp_lwip_sent);
    tcp_recv(pcb, &tcp_lwip_received);
    tcp_err(pcb, &tcp_lwip_err);

    if (conf->proxytype == PROXY_SOCKS5) {
        fwd->proxy = socks_tcp_create(core->loop, &tcp_proxy_io_event, fwd);
    } else if (conf->proxytype == PROXY_HTTP) {
        fwd->proxy = http_tcp_create(core->loop, &tcp_proxy_io_event, fwd);
    } else {
        fwd->proxy = direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd);
    }

    fwd->proxy->connect(fwd->proxy, ipaddr_ntoa(&pcb->local_ip),
                        pcb->local_port);
}

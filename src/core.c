#include "core.h"

#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#include "direct.h"
#include "dns.h"
#include "http.h"
#include "socks.h"

/* try to recv data from proxy server and send to application */
static void udp_proxy_input(struct sk_ops *proxy, struct udp_pcb *pcb)
{
    char buffer[65535];
    ssize_t nread;
    struct pbuf *p;

    nread = proxy->recv(proxy, buffer, sizeof(buffer));
    if (nread > 0) {
        if ((p = pbuf_alloc_reference(buffer, nread, PBUF_REF)) == NULL) {
            fprintf(stderr, "Out of Memory.\n");
            abort();
        }
        udp_send(pcb, p);
        pbuf_free(p);
    }
}

/* try to send data to proxy server, data already in pcb->rcvq */
static void udp_proxy_output(struct sk_ops *proxy, struct udp_pcb *pcb)
{
    char buffer[65535];
    ssize_t i, nsent;
    struct pbuf *p;

    /* send all */
    for (i = 0; i < pcb->nrcvq; i++) {
        p = pcb->rcvq[i];
        if (p->len == p->tot_len) {
            nsent = pcb->proxy->send(pcb->proxy, p->payload, p->tot_len);
        } else {
            pbuf_copy_partial(p, buffer, p->tot_len, 0);
            nsent = pcb->proxy->send(pcb->proxy, buffer, p->tot_len);
        }
        if (nsent > 0) {
            pbuf_free(p);
            continue;
        } else {
            break;
        }
    }

    pcb->nrcvq -= i;

    if (pcb->nrcvq == 0) {
        /* all succeed */
        proxy->evctl(proxy, EPOLLOUT, 0);
    } else {
        /* some failed  */
        memmove(pcb->rcvq, pcb->rcvq + i, pcb->nrcvq * sizeof(pcb->rcvq[0]));
        proxy->evctl(proxy, EPOLLOUT, 1);
    }
}

/* handle event occured in connection connected to proxy server */
static void udp_conn_io_event(void *userp, unsigned int event)
{
    struct udp_pcb *pcb = userp;

    if (event & (EPOLLERR | EPOLLHUP)) {
        pcb->proxy->destroy(pcb->proxy);
        pcb->proxy = NULL;
        udp_remove(pcb);
        return;
    }

    if (event & EPOLLIN) {
        udp_proxy_input(pcb->proxy, pcb);
    }

    if (event & EPOLLOUT) {
        udp_proxy_output(pcb->proxy, pcb);
    }
}

/* called by lwip when data has received from application,
   this funcion push the received data to receive queue
*/
static void udp_lwip_received(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port)
{
    struct sk_ops *proxy = pcb->proxy;

    if (!p) {
        /* should not happen */
        udp_remove(pcb);
        return;
    }

    if (!proxy) {
        /* lost connection to proxy server,
           reply ICMP port unreach message, and release udp pcb
        */
        pbuf_header_force(p, (s16_t)(ip_current_header_tot_len() + UDP_HLEN));
        icmp_port_unreach(ip_current_is_v6(), p);
        pbuf_free(p);
        udp_remove(pcb);
        return;
    }

    if (pcb->nrcvq == arraysizeof(pcb->rcvq)) {
        /* receive queue full, drop oldest data in queue and enqueue this */
        memmove(pcb->rcvq, pcb->rcvq + 1,
                (arraysizeof(pcb->rcvq) - 1) * sizeof(pcb->rcvq[0]));
        pcb->rcvq[arraysizeof(pcb->rcvq) - 1] = p;
    } else {
        pcb->rcvq[pcb->nrcvq++] = p;
    }

    udp_proxy_output(pcb->proxy, pcb);
}

/* called by lwip when a udp connection is create
   this function create a connection to proxy server and set lwip udp_recv() up
*/
void core_udp_new(struct udp_pcb *pcb)
{
    struct loopctx *loop = ip_current_netif()->state;
    struct loopconf *conf = loop_conf(loop);
    char *addr = ipaddr_ntoa(&pcb->local_ip);
    uint16_t port = pcb->local_port;

    udp_recv(pcb, udp_lwip_received, NULL);

    if (port == 53 && conf->dnstype != DNS_REDIR_OFF) {
        /* redir for DNS */
        if (conf->dnstype == DNS_REDIR_DIRECT) {
            pcb->proxy = direct_udp_create(loop, &udp_conn_io_event, pcb);
            pcb->proxy->connect(pcb->proxy, addr, port);
            return;
        }
        if (conf->dnstype == DNS_REDIR_TCP) {
            pcb->proxy = tcpdns_create(loop, &udp_conn_io_event, pcb);
            pcb->proxy->connect(pcb->proxy, conf->dnssrv, port);
            return;
        }
        if (conf->dnstype == DNS_REDIR_UDP) {
            addr = conf->dnssrv;
        }
    }

    if (conf->proxytype == PROXY_SOCKS5) {
        pcb->proxy = socks_udp_create(loop, &udp_conn_io_event, pcb);
        pcb->proxy->connect(pcb->proxy, addr, port);
    } /* else - leave pcb->proxy == NULL, udp_lwip_received() handled this
         situation
      */
}

/* try to recv data from proxy server and send to application */
static void tcp_proxy_input(struct sk_ops *proxy, struct tcp_pcb *pcb)
{
    ssize_t nread;
    struct pbuf *p;
    size_t s = LWIP_MIN(tcp_mss(pcb), tcp_sndbuf(pcb));

    /* is pcb->sndq full ? */
    if (!tcp_sndbuf(pcb) || tcp_sndqueuelen(pcb) > TCP_SND_QUEUELEN - 4) {
        /* full, stop polling more data */
        proxy->evctl(proxy, EPOLLIN, 0);
        return;
    }

    if ((p = pbuf_alloc(PBUF_RAW, s, PBUF_RAM)) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    nread = proxy->recv(proxy, p->payload, s);

    /* shirk, set p->tot_len = nread */
    pbuf_realloc(p, nread);

    if (nread > 0) {
        /* succeed, received some data, now send to application then
           enqueue to pcb->sndq
        */
        if (tcp_write(pcb, p->payload, nread, 0) != ERR_OK) {
            fprintf(stderr, "Out of Memory.\n");
            abort();
        }
        tcp_output(pcb);

        if (pcb->sndq == NULL)
            pcb->sndq = p;
        else
            pbuf_cat(pcb->sndq, p);

        p = NULL;
    } else if (nread == 0) {
        /* proxy server return FIN, send a FIN to application too */
        tcp_shutdown(pcb, 0, 1);
        proxy->evctl(proxy, EPOLLIN, 0);
    } else if (nread == -EAGAIN) {
        /* temporarily unavailable, try again later */
        proxy->evctl(proxy, EPOLLIN, 1);
    } else {
        /* failed, error will handle in tcp_proxy_event() */
        proxy->evctl(proxy, EPOLLIN, 0);
    }

    if (p)
        pbuf_free(p); /* did't enqueue, need to free here */
}

/* try to send data to proxy server, data already in pcb->rcvq */
static void tcp_proxy_output(struct sk_ops *proxy, struct tcp_pcb *pcb)
{
    ssize_t nsent;

    if (pcb->rcvq == NULL) {
        /* no data, stop listen on EPOLLOUT event */
        proxy->evctl(proxy, EPOLLOUT, 0);
        return;
    }

    nsent = proxy->send(proxy, pcb->rcvq->payload, pcb->rcvq->len);
    if (nsent > 0) {
        /* succeed, free rcvq and update window */
        pcb->rcvq = pbuf_free_header(pcb->rcvq, nsent);
        tcp_recved(pcb, nsent);
    } else if (nsent == -EAGAIN) {
        /* temporarily unavailable, try again later */
        proxy->evctl(proxy, EPOLLOUT, 1);
    } else {
        /* failed, error will handle in tcp_proxy_event() */
        proxy->evctl(proxy, EPOLLOUT, 0);
    }
}

/* handle event occured in connection connected to proxy server */
static void tcp_proxy_event(void *userp, unsigned int event)
{
    struct tcp_pcb *pcb = userp;

    if (event & EPOLLERR) {
        pcb->proxy->destroy(pcb->proxy);
        pcb->proxy = NULL;
        tcp_abort(pcb);
        return;
    }

    if (event & EPOLLIN) {
        tcp_proxy_input(pcb->proxy, pcb);
    }

    if (event & EPOLLOUT) {
        tcp_proxy_output(pcb->proxy, pcb);
    }

    if (event & EPOLLHUP) {
        pcb->proxy->destroy(pcb->proxy);
        pcb->proxy = NULL;
        tcp_close(pcb);
    }
}

/* called by lwip when application acked data,
   this funcion free sending queue, and ask more data from proxy server
*/
static err_t tcp_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct sk_ops *proxy = pcb->proxy;

    pcb->sndq = pbuf_free_header(pcb->sndq, len);

    if ((pcb->state == ESTABLISHED || pcb->state == CLOSE_WAIT) &&
        tcp_sndbuf(pcb) > TCP_SNDLOWAT)
        proxy->evctl(proxy, EPOLLIN, 1);

    return ERR_OK;
}

/* called by lwip when data has received from application,
   this funcion push the these data to receive queue
*/
static err_t tcp_lwip_received(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err)
{
    struct sk_ops *proxy = pcb->proxy;

    if (!proxy) {
        /* lost connection to proxy server, abort connection */
        tcp_abort(pcb);
        if (p)
            pbuf_free(p);
        return ERR_ABRT;
    }

    if (!p) {
        /* received FIN from application, send a FIN to proxy server */
        proxy->shutdown(proxy, SHUT_WR);
        return ERR_OK;
    }

    tcp_ack(pcb); /* ack immediately */

    /* enqueue, rcvq should not full */
    if (pcb->rcvq)
        pbuf_cat(pcb->rcvq, p);
    else
        pcb->rcvq = p;

    tcp_proxy_output(pcb->proxy, pcb);

    return ERR_OK;
}

/* called by lwip when a tcp connection is create
   this function create a connection to proxy server and set lwip tcp_*() up
*/
void core_tcp_new(struct tcp_pcb *pcb)
{
    struct loopctx *loop = ip_current_netif()->state;

    tcp_nagle_disable(pcb);

    tcp_sent(pcb, &tcp_lwip_sent);
    tcp_recv(pcb, &tcp_lwip_received);

    if (loop_conf(loop)->proxytype == PROXY_SOCKS5) {
        pcb->proxy = socks_tcp_create(loop, &tcp_proxy_event, pcb);
    } else if (loop_conf(loop)->proxytype == PROXY_HTTP) {
        pcb->proxy = http_tcp_create(loop, &tcp_proxy_event, pcb);
    } else {
        pcb->proxy = direct_tcp_create(loop, &tcp_proxy_event, pcb);
    }

    pcb->proxy->connect(pcb->proxy, ipaddr_ntoa(&pcb->local_ip),
                        pcb->local_port);
}

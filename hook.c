#include <sys/epoll.h>

#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "direct.h"

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    fprintf(stderr, "udp_recv_cb\n");

    pcb->ops->send(pcb->ops, p->payload, p->len);

    pbuf_free(p);
}

void udp_handle_event(void *userp, int event)
{
    struct udp_pcb *pcb = userp;
    char buffer[65536];
    ssize_t nread;
    struct pbuf *pb;

    if (event & EPOLLIN) {
        nread = pcb->ops->recv(pcb->ops, buffer, sizeof(buffer));
        if (nread > 0) {
            pb = pbuf_alloc(PBUF_TRANSPORT, nread, PBUF_RAM);
            pbuf_take(pb, buffer, nread);
            udp_send(pcb, pb);
            pbuf_free(pb);
        }
    }

    if (event & EPOLLOUT) {
        pcb->ops->send(pcb->ops, buffer, 0);
    }

    if (event & (EPOLLERR | EPOLLHUP)) {
        /* udp_pcb_free(pcb); */
        return;
    }
}

void hook_on_udp_new(struct udp_pcb *pcb)
{
    fprintf(stderr, "hook_on_udp_new\n");
    pcb->recv = &udp_recv_cb;
    direct_udp_create(&pcb->ops, netif_default->state, pcb, &udp_handle_event);
    pcb->ops->connect(pcb->ops, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    fprintf(stderr, "tcp_recv_cb\n");

    pcb->flags |= TF_ACK_NOW;
    tcp_output(pcb);

    if (p)
        tcp_write(pcb, p->payload, p->len, TCP_WRITE_FLAG_COPY);

    if (p)
        pbuf_free(p);
    return ERR_OK;
}

void hook_on_tcp_new(struct tcp_pcb *pcb)
{
    fprintf(stderr, "hook_on_tcp_new\n");
    tcp_nagle_disable(pcb);
    pcb->recv = tcp_recv_cb;
}

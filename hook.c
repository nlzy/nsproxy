#include "lwip/tcp.h"
#include "lwip/udp.h"

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    fprintf(stderr, "udp_recv_cb\n");
    udp_sendto(pcb, p, addr, port);
    pbuf_free(p);
}

void hook_on_udp_new(struct udp_pcb *pcb)
{
    fprintf(stderr, "hook_on_udp_new\n");
    pcb->recv = &udp_recv_cb;
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

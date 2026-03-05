#pragma once
#include "common.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

struct tcp_forward {
    struct sk_ops *proxy;
    struct tcp_pcb *pcb;
    struct pbuf *sndq;
    struct pbuf *rcvq;
};

struct udp_forward {
    struct sk_ops *proxy;
    struct udp_pcb *pcb;
    struct pbuf *rcvq[8];
    u16_t nrcvq;
};

void core_udp_new(struct udp_pcb *pcb);
void core_tcp_new(struct tcp_pcb *pcb);

#pragma once
#include "lwip/tcp.h"
#include "lwip/udp.h"

void hook_on_udp_new(struct udp_pcb *pcb);
void hook_on_tcp_new(struct tcp_pcb *pcb);

#pragma once
#include "common.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

void core_udp_new(struct udp_pcb *pcb);
void core_tcp_new(struct tcp_pcb *pcb);

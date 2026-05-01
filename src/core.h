#pragma once
#include "loop.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

struct corectx;

int core_init(struct corectx **core, struct loopctx *loop, int tunfd);
void core_deinit(struct corectx *core);

err_t core_udp_new(struct udp_pcb *pcb);
void core_tcp_new(struct tcp_pcb *pcb);

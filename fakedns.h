#pragma once
#include "lwip/pbuf.h"

int fakedns_create(struct sk_ops **handle, struct context_loop *ctx,
                   void (*userev)(void *userp, unsigned int event),
                   void *userp);
int tcpdns_create(struct sk_ops **handle, struct context_loop *ctx,
                  void (*userev)(void *userp, unsigned int event), void *userp);
void dns_tmr(void);

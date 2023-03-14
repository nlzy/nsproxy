#pragma once
#include "common.h"
#include "loop.h"

int fakedns_create(struct sk_ops **handle, struct loopctx *loop,
                   void (*userev)(void *userp, unsigned int event),
                   void *userp);

int tcpdns_create(struct sk_ops **handle, struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp);

void dns_tmr(void);

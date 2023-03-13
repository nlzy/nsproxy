#pragma once
#include "common.h"
#include "loop.h"

int direct_udp_create(struct sk_ops **handle, struct loopctx *loop,
                      void (*userev)(void *userp, unsigned int event),
                      void *userp);

int direct_tcp_create(struct sk_ops **handle, struct loopctx *loop,
                      void (*userev)(void *userp, unsigned int event),
                      void *userp);

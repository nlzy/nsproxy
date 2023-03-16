#pragma once
#include "common.h"
#include "loop.h"

struct sk_ops *
direct_tcp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp);

struct sk_ops *
direct_udp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp);

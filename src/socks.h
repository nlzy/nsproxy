#pragma once
#include "common.h"
#include "loop.h"

struct sk_ops *socks_udp_create(struct loopctx *loop,
                                void (*userev)(void *userp, unsigned int event),
                                void *userp);

struct sk_ops *socks_tcp_create(struct loopctx *loop,
                                void (*userev)(void *userp, unsigned int event),
                                void *userp);

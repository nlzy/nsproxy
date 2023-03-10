#pragma once
#include "common.h"
#include "loop.h"

int socks_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp);

int socks_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                     void (*userev)(void *userp, unsigned int event),
                     void *userp);

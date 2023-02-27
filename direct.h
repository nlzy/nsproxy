#pragma once
#include <stddef.h>

#include "loop.h"

int direct_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, unsigned int event));

int direct_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, unsigned int event));

#pragma once
#include <stddef.h>

#include "loop.h"

int socks_udp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, unsigned int event));

int socks_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                      void *userp, void (*userev)(void *userp, unsigned int event));

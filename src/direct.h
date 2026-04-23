#pragma once
#include "skops.h"
#include "loop.h"

struct sk_ops *
direct_tcp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port);

struct sk_ops *
direct_udp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port);

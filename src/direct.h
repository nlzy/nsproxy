#pragma once
#include "proxy.h"
#include "loop.h"

struct proxy *
direct_tcp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port);

struct proxy *
direct_udp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port);

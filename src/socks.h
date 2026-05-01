#pragma once
#include "proxy.h"
#include "loop.h"

struct proxy *socks_udp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *addr, uint16_t port,
                               struct proxy *assoc);

struct proxy *socks_tcp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *addr, uint16_t port);

struct proxy *socks_assoc_create(struct loopctx *loop, userev_fn_t *userev,
                                 void *userp);

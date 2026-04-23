#pragma once
#include "skops.h"
#include "loop.h"

struct sk_ops *http_tcp_create(struct loopctx *loop,
                               void (*userev)(void *userp, unsigned int event),
                               void *userp, const char *addr, uint16_t port);

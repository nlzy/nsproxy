#pragma once
#include "common.h"
#include "loop.h"

int http_tcp_create(struct sk_ops **handle, struct context_loop *ctx,
                    void (*userev)(void *userp, unsigned int event),
                    void *userp);

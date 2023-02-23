#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "common.h"

struct context_loop;

void loop_init(struct context_loop **ctx, int tunfd, int sigfd);
void loop_deinit(struct context_loop *ctx);
int loop_run(struct context_loop *ctx);
int loop_epfd(struct context_loop *ctx);

struct sk_ops {
    int (*connect)(struct sk_ops *handle, const char *addr, uint16_t port);
    int (*shutdown)(struct sk_ops *handle, int how);
    ssize_t (*send)(struct sk_ops *handle, const char *data, size_t len);
    ssize_t (*recv)(struct sk_ops *handle, char *data, size_t len);
    void (*destroy)(struct sk_ops *handle);
};

struct ep_poller {
    void (*on_epoll_event)(struct ep_poller *poller, int event);
};

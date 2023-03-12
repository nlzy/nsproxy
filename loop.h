#pragma once
#include "common.h"

struct context_loop;

enum {
    DNSHIJACK_OFF,
    DNSHIJACK_PROXY,
    DNSHIJACK_TCP,
    DNSHIJACK_UDP
};

enum {
    PROXY_SOCKS5,
    PROXY_HTTP
};

struct loopconf {
    char proxysrv[512];
    char proxyport[16];
    uint8_t proxytype;
    char dnssrv[512];
    uint8_t dnstype;
};

void loop_init(struct context_loop **ctx, struct loopconf *conf, int tunfd, int sigfd);
void loop_deinit(struct context_loop *ctx);
int loop_run(struct context_loop *ctx);
int loop_epfd(struct context_loop *ctx);
struct loopconf *loop_conf(struct context_loop *ctx);

struct sk_ops {
    int (*connect)(struct sk_ops *handle, const char *addr, uint16_t port);
    int (*shutdown)(struct sk_ops *handle, int how);
    void (*evctl)(struct sk_ops *handle, unsigned int event, int enable);
    ssize_t (*send)(struct sk_ops *handle, const char *data, size_t len);
    ssize_t (*recv)(struct sk_ops *handle, char *data, size_t len);
    void (*destroy)(struct sk_ops *handle);
};

struct ep_poller {
    void (*on_epoll_event)(struct ep_poller *poller, unsigned int event);
};

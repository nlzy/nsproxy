#pragma once
#include "common.h"

struct loopctx;

enum {
    DNS_REDIR_OFF,
    DNS_REDIR_DIRECT,
    DNS_REDIR_TCP,
    DNS_REDIR_UDP
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

void loop_init(struct loopctx **loop, struct loopconf *conf, int tunfd, int sigfd);
void loop_deinit(struct loopctx *loop);
int loop_run(struct loopctx *loop);
int loop_epfd(struct loopctx *loop);
struct loopconf *loop_conf(struct loopctx *loop);

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

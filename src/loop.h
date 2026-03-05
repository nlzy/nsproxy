#pragma once
#include "common.h"

struct loopctx;

enum {
    DNS_REDIR_OFF,
    DNS_REDIR_TCP,
    DNS_REDIR_UDP
};

enum {
    PROXY_SOCKS5,
    PROXY_HTTP,
    PROXY_DIRECT
};

struct loopconf {
    char proxysrv[64];
    char proxyport[8];
    uint8_t proxytype;
    char dnssrv[128];
    uint8_t dnstype;
    char proxyuser[64];   /* Proxy username for authentication */
    char proxypass[64];   /* Proxy password for authentication */
};

void loop_init(struct loopctx **loop, struct loopconf *conf, int tunfd,
               int sigfd);
void loop_deinit(struct loopctx *loop);
int loop_run(struct loopctx *loop);
struct loopconf *loop_conf(struct loopctx *loop);

struct epcb_ops {
    void (*on_epoll_events)(struct epcb_ops *conn, unsigned int events);
};

void loop_epoll_ctl(struct loopctx *loop, int op, int fd, unsigned events,
                    struct epcb_ops *epcb);

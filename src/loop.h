#pragma once
#include "common.h"

struct loopctx;

int loop_init(struct loopctx **loop, int sigfd);
void loop_deinit(struct loopctx *loop);
int loop_run(struct loopctx *loop);

struct epcb_ops {
    void (*on_epoll_events)(struct epcb_ops *conn, unsigned int events);
};

int loop_epoll_ctl(struct loopctx *loop, int op, int fd, unsigned events,
                   struct epcb_ops *epcb);

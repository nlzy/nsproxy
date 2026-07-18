/*
 * Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "loop.h"

#include <sys/epoll.h>

struct loopctx {
    int epfd;
    struct csigctx *csig;
};

int loop_init(struct loopctx **loop, struct csigctx *csig)
{
    struct loopctx *p;
    struct epoll_event ev;

    if ((p = malloc(sizeof(struct loopctx))) == NULL)
        oom();

    if ((p->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        loglv0("loop_init: epoll_create1() failed: %s", strerror(errno));
        goto failed_after_malloc;
    }

    p->csig = csig;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->csig; /* use our ctx address which is private */
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, csig->sigfd, &ev) == -1) {
        loglv0("loop_init: epoll_ctl(sigfd) failed: %s", strerror(errno));
        goto failed_after_epoll_create;
    }

    loginfo("loop_init: initialized event loop (loopctx)");

    *loop = p;
    return 0;

failed_after_epoll_create:
    close(p->epfd);
failed_after_malloc:
    free(p);
    return -1;
}

void loop_deinit(struct loopctx *loop)
{
    close(loop->epfd);
    free(loop);
}

int loop_run(struct loopctx *loop)
{
    int i, nevent, ret;
    /* profile shows event polling and context switching is not the bottleneck,
       batch polling risks event caching, see pitfalls in 'man 7 epoll' */
    struct epoll_event ev[1];

    for (;;) {
        if ((nevent = epoll_wait(loop->epfd, ev, arraysizeof(ev), -1)) == -1) {
            if (errno == EINTR)
                continue;
            loglv0("loop_run: epoll_wait() failed: %s", strerror(errno));
            return -1;
        }
        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &loop->csig) {
                if ((ret = csignal_handler(loop->csig)) == 0)
                    continue;
                if (ret > 0)
                    loglv1("All child exited, cleaning ...");
                else
                    loglv0("loop_run: signal handler failed: %s", strerror(-ret));
                return ret > 0 ? 0 : -1;
            } else {
                struct epcb_ops *epcb = ev[i].data.ptr;
                epcb->on_epoll_events(epcb, ev[i].events);
            }
        }
    }
}

int loop_epoll_ctl(struct loopctx *loop, int op, int fd, unsigned events,
                   struct epcb_ops *epcb)
{
    struct epoll_event ev = { .events = events, .data.ptr = epcb };
    return (epoll_ctl(loop->epfd, op, fd, &ev) == -1) ? -errno : 0;
}

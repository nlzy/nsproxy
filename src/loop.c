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

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

struct loopctx {
    int sigfd;
    int epfd;
};

/* handle SIGCHLD, nsproxy exits after all child processes exit
   returns:
   - -EAGAIN: child still alive
   - >= 0: exit status of last child
   - < 0: error
*/
static int sigfd_handler(struct loopctx *loop)
{
    struct signalfd_siginfo sig;
    pid_t pid;
    int stat, exited, exitcode = 0;

    if (read(loop->sigfd, &sig, sizeof(sig)) == -1)
        return -errno;

    /* we never add signals other than SIGCHLD to the sigmask,
       this should not happen */
    if (sig.ssi_signo != SIGCHLD)
        return -EINVAL;

    /* reap all exited children */
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        if (!WIFEXITED(stat) && !WIFSIGNALED(stat))
            continue; /* child not dead */
        exited = WIFEXITED(stat);
        exitcode = exited ? WEXITSTATUS(stat) : (128 + WTERMSIG(stat));
        loglv1("Child process %d %s %d", pid,
               exited ? "exited with status" : "killed by signal",
               exited ? WEXITSTATUS(stat) : WTERMSIG(stat));
    }

    /* no child could be reaped, may some still running, or all exited */

    if (pid == -1 && errno == ECHILD) {
        loglv1("All child exited, cleaning ...");
        return exitcode;
    } else if (pid == -1) {
        int ret = -errno;
        logwarn("sigfd_handler: waitpid() failed: %s", strerror(errno));
        return ret;
    } else {
        assert(pid == 0);
        return -EAGAIN;
    }
}

int loop_init(struct loopctx **loop, int sigfd)
{
    struct loopctx *p;
    struct epoll_event ev;

    if ((p = malloc(sizeof(struct loopctx))) == NULL)
        oom();

    if ((p->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        loglv0("loop_init: epoll_create1() failed: %s", strerror(errno));
        goto failed_after_malloc;
    }

    p->sigfd = sigfd;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->sigfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
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
            return -errno;
        }
        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &loop->sigfd) {
                if ((ret = sigfd_handler(loop)) != -EAGAIN)
                    return ret;
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

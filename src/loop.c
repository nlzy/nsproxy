#include "loop.h"

#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <unistd.h>

struct loopctx {
    int sigfd;
    int epfd;
};

/* handle SIGCHLD, nsproxy exits after all child processes exit */
static int sigfd_handler(struct loopctx *loop)
{
    struct signalfd_siginfo sig;
    pid_t pid;
    int status;
    int exitcode = 0;

    if (read(loop->sigfd, &sig, sizeof(sig)) == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;
        }
        perror("read()");
        abort();
    }

    /* we never add signals other than SIGCHLD to the sigmask,
       this should not happen */
    if (sig.ssi_signo != SIGCHLD)
        return -1;

    /* reap all exited children */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            exitcode = WEXITSTATUS(status);
            loglv(1, "Child process %d exited with status %d",
                     pid, exitcode);
        } else if (WIFSIGNALED(status)) {
            exitcode = 128 + WTERMSIG(status);
            loglv(1, "Child process %d killed by signal %d",
                     pid, WTERMSIG(status));
        }
    }

    /* no child could be reaped, may some still running, or all exited */

    if (pid == 0) {
        /* still running, continue event loop */
        return -1;
    } else if (errno == ECHILD) {
        /* all exited, exit nsproxy */
        loglv(1, "All child exited, nsproxy is closing. Bye ~");
        return exitcode;
    } else {
        loglv(3, "waitpid() failed: %s", strerror(errno));
        return -1;
    }
}

int loop_init(struct loopctx **loop, int sigfd)
{
    struct loopctx *p;
    struct epoll_event ev;

    if ((p = malloc(sizeof(struct loopctx))) == NULL)
        oom();

    if ((p->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        loglv(0, "loop_init: epoll_create1() failed: %s", strerror(errno));
        goto err_free_p;
    }

    p->sigfd = sigfd;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->sigfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
        loglv(0, "loop_init: epoll_ctl(sigfd) failed: %s", strerror(errno));
        goto err_close_epfd;
    }

    loglv(3, "loop_init: lwIP and event loop initialized");

    *loop = p;
    return 0;

err_close_epfd:
    close(p->epfd);
err_free_p:
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
    int i, nevent;
    struct epoll_event ev[1];

    for (;;) {
        if ((nevent = epoll_wait(loop->epfd, ev, arraysizeof(ev), -1)) == -1) {
            if (errno != EINTR) {
                perror("epoll_wait()");
                abort();
            }
        }
        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &loop->sigfd) {
                int rc;
                if ((rc = sigfd_handler(loop)) != -1) {
                    return rc;
                }
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
    int err;
    struct epoll_event ev;

    ev.events = events;
    ev.data.ptr = epcb;
    if ((err = epoll_ctl(loop->epfd, op, fd, &ev)) == -1) {
        if (errno == EEXIST) {
            loglv(3, "loop_epoll_ctl: fd %d is registered already", fd);
        } else if (errno == ENOENT) {
            loglv(3, "loop_epoll_ctl: fd %d is not registered", fd);
        } else {
            fprintf(stderr, "epoll_ctl(%d) failed: %s\n", op, strerror(errno));
            abort();
        }
    }

    return err;
}

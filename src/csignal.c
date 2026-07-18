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
#include "csignal.h"

#include <signal.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

/* Receive SIGCHLD via signalfd. This function setup sigprocmask, create a
   signalfd, then become subreaper. Return the fd on success, -errno on failed. */
int csignal_initfd(void)
{
    int sigfd;
    sigset_t mask;

    /* mask = SIGCHLD */
    if (sigemptyset(&mask) == -1)
        return -errno;
    if (sigaddset(&mask, SIGCHLD) == -1)
        return -errno;

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
        return -errno;

    if ((sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK)) == -1)
        return -errno;

    /* receive SIGCHLD for grandchilds */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1)
        loglv0("Warning: Failed to set child subreaper, grandchild processes "
               "may not be tracked.");

    return sigfd;
}

/* Handle SIGCHLD, nsproxy exits after all child processes exit. Returns:
   - 0: children still living
   - 1: children all exited
   - <0: -errno
*/
int csignal_handler(struct csigctx *csig)
{
    struct signalfd_siginfo sig;
    pid_t pid;
    int stat;

    if (read(csig->sigfd, &sig, sizeof(sig)) == -1) {
        if (errno == EAGAIN)
            return 0;
        return -errno;
    }

    /* sanity check: we only added SIGCHLD to the sigmask */
    if (sig.ssi_signo != SIGCHLD)
        return -EINVAL;

    /* reap child and grand children */
    while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        int exited = WIFEXITED(stat);
        int killed = WIFSIGNALED(stat);

        if (!exited && !killed)
            continue;

        if (pid == csig->cid)
            csig->rc = exited ? WEXITSTATUS(stat) : (128 + WTERMSIG(stat));

        loglv1("Child process %d %s %d", pid,
               exited ? "exited with status" : "killed by signal",
               exited ? WEXITSTATUS(stat) : WTERMSIG(stat));
    }

    if (pid == -1 && errno != ECHILD)
        return -errno;

    if (pid == -1)
        return 1; /* children all exited */

    return 0; /* children still living */
}

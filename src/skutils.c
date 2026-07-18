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
#include "skutils.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "proxy.h"

int skutils_connect(struct skinfo *info, const char *ip, uint16_t port, int type)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_flags = AI_NUMERICHOST };
    struct addrinfo *ai;
    char portstr[8];
    int sfd;

    if (strlen(ip) > IP_MAXLEN)
        return -EINVAL;

    snprintf(portstr, sizeof(portstr), "%u", (unsigned int)port);

    /* resolve string ip to sockaddr, works well with both IPv4 / IPv6 */
    if (getaddrinfo(ip, portstr, &hints, &ai) != 0)
        return -EADDRNOTAVAIL;

    sfd = socket(ai->ai_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sfd == -1) {
        int ret = -errno;
        freeaddrinfo(ai);
        return ret;
    }

    /* try to enable TCP_NODELAY, failure is not checked */
    if (type == SOCK_STREAM)
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

    if (connect(sfd, ai->ai_addr, ai->ai_addrlen) == -1) {
        if (errno != EINPROGRESS) {
            int ret = -errno;
            freeaddrinfo(ai);
            close(sfd);
            return ret;
        }
    }

    loglv1("%s %s:%u/%s", type == SOCK_STREAM ? "Connecting" : "Forwarding",
           info->addr, (unsigned)info->port, info->proto);
    freeaddrinfo(ai);
    return sfd;
}

int skutils_evctl(struct loopctx *loop, int sfd, unsigned int *events,
                  struct epcb_ops *epcb, unsigned int mask, int mode)
{
    unsigned int new_events, old_events = *events;

    switch (mode) {
        case EVCLR: new_events = old_events & ~mask; break;
        case EVSET: new_events = old_events | mask;  break;
        case EVUPD: new_events = mask;               break;
        default: return -EINVAL;
    }

    if (old_events != new_events) {
        int op, err;

        op = (old_events == 0) ? EPOLL_CTL_ADD :
             (new_events == 0) ? EPOLL_CTL_DEL :
                                 EPOLL_CTL_MOD;
        if ((err = loop_epoll_ctl(loop, op, sfd, new_events, epcb)) < 0) {
            logwarn("skutils_evctl: loop_epoll_ctl failed: %s", strerror(-err));
            return err;
        }

        *events = new_events;
    }

    return 0;
}

ssize_t skutils_send(struct skinfo *info, int sfd, const char *data,
                     size_t size)
{
    ssize_t nsent;

    if ((nsent = send(sfd, data, size, MSG_NOSIGNAL)) == -1)
        return -errno;

    info->nsent += nsent;

    loglv2("--- %zd bytes sent to %s:%u/%s", nsent, info->addr,
           (unsigned)info->port, info->proto);
    return nsent;
}

ssize_t skutils_sendmsg(struct skinfo *info, int sfd, struct msghdr *msg)
{
    ssize_t nsent;

    if ((nsent = sendmsg(sfd, msg, MSG_NOSIGNAL)) == -1)
        return -errno;

    info->nsent += nsent;

    loglv2("--- %zd bytes sent to %s:%u/%s", nsent, info->addr,
           (unsigned)info->port, info->proto);
    return nsent;
}

ssize_t skutils_recv(struct skinfo *info, int sfd, char *data, size_t size)
{
    ssize_t nread;

    if ((nread = recv(sfd, data, size, 0)) == -1)
        return -errno;

    info->nread += nread;

    loglv2("+++ %zd bytes received from %s:%u/%s", nread, info->addr,
           (unsigned)info->port, info->proto);
    return nread;
}

int skutils_shutdown(struct skinfo *info, struct loopctx *loop, int *sfd,
                     int how, int rst)
{
    if (rst) {
        struct linger lng = { 1, 0 };
        setsockopt(*sfd, SOL_SOCKET, SO_LINGER, &lng, sizeof(lng));
        skutils_close_unreg(info, loop, sfd);
    } else {
        if (shutdown(*sfd, how) == -1)
            return -errno;
    }

    loglv2("... shutdown %s:%u/%s", info->addr, (unsigned)info->port,
           info->proto);
    return 0;
}

void skutils_close_unreg(struct skinfo *info, struct loopctx *loop, int *sfd)
{
    int err;

    if (*sfd == -1)
        return;

    if ((err = loop_epoll_ctl(loop, EPOLL_CTL_DEL, *sfd, 0, NULL)) < 0)
        if (err != -ENOENT)
            logwarn("skutils_close_unreg: remove fd from epoll failed: %s",
                    strerror(-err));

    if (close(*sfd) == -1)
        logwarn("skutils_close_unreg: close fd failed: %s", strerror(errno));

    *sfd = -1;

    if (info)
        loglv1("Closed %s:%u/%s (sent %zu, received %zu bytes)", info->addr,
               (unsigned)info->port, info->proto, info->nsent, info->nread);
}

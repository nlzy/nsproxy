#include "skutils.h"
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

int skutils_connect(struct skinfo *info, const char *addr, uint16_t port,
                    int type)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *ai;
    char portstr[8];
    int sfd;

    if (strlen(addr) >= SERVNAME_MAXLEN)
        return -EINVAL;

    snprintf(portstr, sizeof(portstr), "%u", (unsigned int)port);

    /* reslove string addr to sockaddr, works well with both IPv4 / IPv6 */
    if (getaddrinfo(addr, portstr, &hints, &ai) != 0)
        return -EADDRNOTAVAIL;

    sfd = socket(ai->ai_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sfd == -1) {
        freeaddrinfo(ai);
        return -errno;
    }

    /* try to enable TCP_NODELAY, failure is not checked */
    if (type == SOCK_STREAM)
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));

    if (connect(sfd, ai->ai_addr, ai->ai_addrlen) == -1) {
        if (errno != EINPROGRESS) {
            freeaddrinfo(ai);
            close(sfd);
            return -errno;
        }
    }

    snprintf(info->desc, sizeof(info->desc), "%s:%u/%s", addr,
             (unsigned)port, type == SOCK_STREAM ? "tcp" : "udp");

    loglv(1, "%s %s", type == SOCK_STREAM ? "Forwarding" : "Connecting",
             info->desc);
    freeaddrinfo(ai);
    return sfd;
}

int skutils_evctl(struct skinfo *info, struct loopctx *loop, int sfd,
                  unsigned int *events, struct epcb_ops *epcb,
                  unsigned int mask, int enable)
{
    int err = 0;
    unsigned int old_events = *events;
    unsigned int new_events = enable ? (old_events | mask)
                                     : (old_events & ~mask);

    if (old_events != new_events) {
        int op = (old_events == 0) ? EPOLL_CTL_ADD :
                 (new_events == 0) ? EPOLL_CTL_DEL :
                                     EPOLL_CTL_MOD;
        err = loop_epoll_ctl(loop, op, sfd, new_events, epcb);
        *events = new_events;
    }

    return err;
}

ssize_t skutils_send(struct skinfo *info, int sfd, const char *data,
                     size_t size)
{
    ssize_t nsent;

    if ((nsent = send(sfd, data, size, MSG_NOSIGNAL)) == -1)
        return -errno;

    info->nsent += nsent;

    loglv(2, "--- send %zd bytes via %s", nsent, info->desc);
    return nsent;
}

ssize_t skutils_sendmsg(struct skinfo *info, int sfd, struct msghdr *msg)
{
    ssize_t nsent;

    if ((nsent = sendmsg(sfd, msg, MSG_NOSIGNAL)) == -1)
        return -errno;

    info->nsent += nsent;

    loglv(2, "--- send %zd bytes via %s", nsent, info->desc);
    return nsent;
}

ssize_t skutils_recv(struct skinfo *info, int sfd, char *data, size_t size)
{
    ssize_t nread;

    if ((nread = recv(sfd, data, size, 0)) == -1)
        return -errno;

    info->nread += nread;

    loglv(2, "+++ recv %zd bytes via %s", nread, info->desc);
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

    loglv(2, "... shutdown %s", info->desc);
    return 0;
}

void skutils_close_unreg(struct skinfo *info, struct loopctx *loop, int *sfd)
{
    if (*sfd == -1)
        return;

    if (loop_epoll_ctl(loop, EPOLL_CTL_DEL, *sfd, 0, NULL) < 0)
        loglv(0, "skutils_close_unreg: remove fd from epoll failed");

    if (close(*sfd) == -1)
        loglv(0, "skutils_close_unreg: close fd failed: %s", strerror(errno));

    *sfd = -1;

    loglv(1, "Closed %s (sent %zu, recieved %zu bytes)",
             info->desc, info->nsent, info->nread);
}

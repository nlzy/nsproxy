

#include "skcomm.h"
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

int skcomm_common_connect(struct sk_comm *comm, const char *addr,
                          uint16_t port)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    char strport[8];

    if (strlen(addr) >= SERVNAME_MAXLEN)
        return -EINVAL;

    snprintf(strport, sizeof(strport), "%u", (unsigned int)port);

    /* reslove string to sockaddr,
       no need to determine what type the address is
    */
    if (getaddrinfo(addr, strport, &hints, &result) != 0)
        return -1;

    comm->sfd = socket(result->ai_family,
                       comm->stype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (comm->sfd == -1) {
        perror("socket()");
        abort();
    }

    if (comm->stype == SOCK_STREAM) {
        if (setsockopt(comm->sfd, IPPROTO_TCP, TCP_NODELAY, &(const int){ 1 },
                       sizeof(int)) == -1) {
            perror("setsockopt()");
            abort();
        }
    }

    if (connect(comm->sfd, result->ai_addr, result->ai_addrlen) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("connect()");
            abort();
        }
    }

    freeaddrinfo(result);

    snprintf(comm->desc, sizeof(comm->desc), "%s:%u/%s", addr, (unsigned)port,
             comm->stype == SOCK_STREAM ? "tcp" : "udp");

    loglv(1, "%s %s", comm->stype == SOCK_STREAM ? "Forwarding" : "Connected",
             comm->desc);

    return 0;
}

void skcomm_common_evctl(struct sk_comm *comm, unsigned int event, int enable)
{
    unsigned int new_events = enable ? (comm->events | event)
                                     : (comm->events & ~event);

    if (new_events != comm->events) {
        int op = (comm->events == 0) ? EPOLL_CTL_ADD :
                 (new_events == 0)   ? EPOLL_CTL_DEL :
                                       EPOLL_CTL_MOD;
        loop_epoll_ctl(comm->loop, op, comm->sfd, new_events, &comm->epcb);
        comm->events = new_events;
    }
}

ssize_t skcomm_common_send(struct sk_comm *comm, const char *data, size_t size)
{
    ssize_t nsent;

    nsent = send(comm->sfd, data, size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    comm->nsent += nsent;
    loglv(2, "--- send %zd bytes via %s", nsent, comm->desc);

    return nsent;
}

ssize_t skcomm_common_sendmsg(struct sk_comm *comm, struct msghdr *msg)
{
    ssize_t nsent;

    nsent = sendmsg(comm->sfd, msg, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("sendmsg()");
            abort();
        }
    }

    comm->nsent += nsent;
    loglv(2, "--- send %zd bytes via %s", nsent, comm->desc);

    return nsent;
}

ssize_t skcomm_common_recv(struct sk_comm *comm, char *data, size_t size)
{
    ssize_t nread;

    nread = recv(comm->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    comm->nread += nread;
    loglv(2, "+++ recv %zd bytes via %s", nread, comm->desc);

    return nread;
}

int skcomm_common_shutdown(struct sk_comm *comm, int how, int rst)
{
    if (comm->stype == SOCK_DGRAM)
        return -EINVAL;

    if (rst) {
        struct linger lng = { 1, 0 };
        if (setsockopt(comm->sfd,
                       SOL_SOCKET, SO_LINGER, &lng, sizeof(lng)) == -1) {
            perror("setsockopt()");
            abort();
        }
        skcomm_common_close(comm);
        return 0;
    } else {
        int ret;
        if ((ret = shutdown(comm->sfd, how)) == -1) {
            if (is_ignored_skerr(errno)) {
                return -errno;
            } else {
                perror("shutdown()");
                abort();
            }
        }
        return ret;
    }
}

void skcomm_common_close(struct sk_comm *comm)
{
    if (comm->sfd != -1) {
        loop_epoll_ctl(comm->loop, EPOLL_CTL_DEL, comm->sfd, 0, NULL);
        if (close(comm->sfd) == -1) {
            perror("close()");
            abort();
        }
        comm->sfd = -1;
        loglv(1, "Closed %s (sent %zu, recieved %zu bytes)",
                 comm->desc, comm->nsent, comm->nread);
    }
}

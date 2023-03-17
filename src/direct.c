#include "direct.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"

struct conn_direct {
    struct sk_ops ops;
    struct loopctx *loop;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    int isudp;
    char *addr;
    uint16_t port;

    int sfd;
    struct ep_poller io_poller;
    struct epoll_event io_poller_ev;
};

/* epoll event callback, just forward event to user */
void direct_io_event(struct ep_poller *poller, unsigned int event)
{
    struct conn_direct *self =
        container_of(poller, struct conn_direct, io_poller);
    self->userev(self->userp, event);
}

/* impl for struct sk_ops :: connect */
int direct_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    char strport[8];
    int sktype = self->isudp ? SOCK_DGRAM : SOCK_STREAM;
    int const enable = 1;

    if (strlen(addr) >= 128)
        return -1;

    snprintf(strport, sizeof(strport), "%u", (unsigned int)port);

    /* reslove string to sockaddr,
       no need to determine what type the address is
    */
    getaddrinfo(addr, strport, &hints, &result);

    if ((self->sfd = socket(result->ai_family,
                            sktype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        abort();
    }

    if (!self->isudp) {
        if (setsockopt(self->sfd, IPPROTO_TCP, TCP_NODELAY, &enable,
                       sizeof(int)) == -1) {
            perror("setsockopt()");
            abort();
        }
    }

    if (connect(self->sfd, result->ai_addr, result->ai_addrlen) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("connect()");
            abort();
        }
    }

    freeaddrinfo(result);

    self->io_poller.on_epoll_event = &direct_io_event;
    self->io_poller_ev.events = EPOLLIN | EPOLLOUT;
    self->io_poller_ev.data.ptr = &self->io_poller;
    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_ADD, self->sfd,
                  &self->io_poller_ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    self->addr = strdup(addr);
    self->port = port;

    return 0;
}

/* impl for struct sk_ops :: shutdown */
int direct_shutdown(struct sk_ops *conn, int how)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    int ret;

    if ((ret = shutdown(self->sfd, how)) == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("shutdown()");
            abort();
        }
    }

    return ret;
}

/* impl for struct sk_ops :: evctl */
void direct_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    unsigned int old = self->io_poller_ev.events;

    if (enable) {
        self->io_poller_ev.events |= event;
    } else {
        self->io_poller_ev.events &= ~event;
    }

    if (old != self->io_poller_ev.events) {
        if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_MOD, self->sfd,
                      &self->io_poller_ev) == -1) {
            perror("epoll_ctl()");
            abort();
        }
    }
}

/* impl for struct sk_ops :: send */
ssize_t direct_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    ssize_t nsent;

    nsent = send(self->sfd, data, size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (is_ignored_skerr(errno)) {
            nsent = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    loglv(3, "--- direct %zd bytes. %s:%s:%u", nsent,
          self->isudp ? "udp" : "tcp", self->addr, (unsigned)self->port);

    return nsent;
}

/* impl for struct sk_ops :: recv */
ssize_t direct_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    ssize_t nread;

    nread = recv(self->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            nread = -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    loglv(3, "+++ direct %zd bytes. %s:%s:%u", nread,
          self->isudp ? "udp" : "tcp", self->addr, (unsigned)self->port);

    return nread;
}

/* impl for struct sk_ops :: destory */
void direct_destroy(struct sk_ops *conn)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);

    if (epoll_ctl(loop_epfd(self->loop), EPOLL_CTL_DEL, self->sfd, NULL) ==
        -1) {
        perror("epoll_ctl()");
        abort();
    }

    if (shutdown(self->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    if (close(self->sfd) == -1) {
        perror("close()");
        abort();
    }

    free(self->addr);

    free(self);
}

/* used for internal only */
static struct conn_direct *direct_create_internel(void)
{
    struct conn_direct *self;

    if ((self = malloc(sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->ops.connect = &direct_connect;
    self->ops.shutdown = &direct_shutdown;
    self->ops.evctl = &direct_evctl;
    self->ops.send = &direct_send;
    self->ops.recv = &direct_recv;
    self->ops.destroy = &direct_destroy;

    return self;
}

/* create a tcp connection
   will connect directly via local network */
struct sk_ops *
direct_tcp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_direct *self = direct_create_internel();

    self->isudp = 0;
    self->loop = loop;
    self->userev = userev;
    self->userp = userp;

    return &self->ops;
}

/* create a udp connection
   will connect directly via local network */
struct sk_ops *
direct_udp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_direct *self = direct_create_internel();

    self->isudp = 1;
    self->loop = loop;
    self->userev = userev;
    self->userp = userp;

    return &self->ops;
}

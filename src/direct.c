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
    unsigned int events;
};

static void direct_epoll_ctl(struct conn_direct *self, int op, unsigned events)
{
    struct epoll_event ev;

    self->events = events;

    /* do epoll_ctl() */
    ev.events = self->events;
    ev.data.ptr = &self->ops;
    if (epoll_ctl(loop_epfd(self->loop), op, self->sfd, &ev) == -1) {
        fprintf(stderr, "epoll_ctl(%d) failed: %s\n", op, strerror(errno));
        abort();
    }
}

/* epoll event callback, just forward event to user */
static void direct_poller_event(struct sk_ops *conn, unsigned int event)
{
    struct conn_direct *self =
        container_of(conn, struct conn_direct, ops);
    self->userev(self->userp, event);
}

/* impl for struct sk_ops :: connect */
static int direct_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    char strport[8];
    int sktype = self->isudp ? SOCK_DGRAM : SOCK_STREAM;
    int const enable = 1;

    loglv(3, "direct_connect: connecting %s:%u/%s",
             addr, (unsigned)port, self->isudp ? "udp" : "tcp");

    if (strlen(addr) >= 128)
        return -1;

    snprintf(strport, sizeof(strport), "%u", (unsigned int)port);

    /* reslove string to sockaddr,
       no need to determine what type the address is
    */
    if (getaddrinfo(addr, strport, &hints, &result) != 0)
        return -1;

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

    self->addr = strdup(addr);
    self->port = port;

    if (self->isudp) {
        loglv(1, "Forwarding %s:%u/udp", addr, (unsigned)port);
    } else {
        loglv(1, "Connected %s:%u/tcp", addr, (unsigned)port);
    }

    direct_epoll_ctl(self, EPOLL_CTL_ADD, EPOLLOUT | EPOLLIN);

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int direct_shutdown(struct sk_ops *conn, int how)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    int ret;

    loglv(3, "direct_shutdown: shutting down %s:%u/%s",
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

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
static void direct_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    unsigned int new_events = self->events;

    if (enable) {
        new_events |= event;
    } else {
        new_events &= ~event;
    }

    if (new_events != self->events)
        direct_epoll_ctl(self, EPOLL_CTL_MOD, new_events);
}

/* impl for struct sk_ops :: send */
static ssize_t direct_send(struct sk_ops *conn, const char *data, size_t size)
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

    loglv(2, "--- direct %zd bytes. %s:%u/%s", nsent,
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

    return nsent;
}

/* impl for struct sk_ops :: recv */
static ssize_t direct_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    ssize_t nread;

    nread = recv(self->sfd, data, size, 0);
    if (nread == -1) {
        if (is_ignored_skerr(errno)) {
            return -errno;
        } else {
            perror("send()");
            abort();
        }
    }

    loglv(2, "+++ direct %zd bytes. %s:%u/%s", nread,
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

    return nread;
}

/* impl for struct sk_ops :: destory */
static void direct_destroy(struct sk_ops *conn)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);

    loglv(3, "direct_destroy: destroying %s:%u/%s",
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

    direct_epoll_ctl(self, EPOLL_CTL_DEL, 0);

    if (shutdown(self->sfd, SHUT_RDWR) == -1) {
        if (!is_ignored_skerr(errno)) {
            perror("shutdown()");
            abort();
        }
    }

    loglv(1, "Closed %s:%u", self->addr, (unsigned)self->port);

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

    loglv(3, "direct_create_internel: creating a new struct conn_direct");

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
    self->ops.on_event = &direct_poller_event;

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

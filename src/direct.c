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

    struct epcb_ops epcb;

    int refcnt;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    int isudp;
    char *addr;
    uint16_t port;

    int sfd;
    unsigned int events;

    size_t nsent;
    size_t nread;
};

/* epoll event callback, just forward event to user */
static void direct_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct conn_direct *self =
        container_of(epcb, struct conn_direct, epcb);
    self->userev(self->userp, events);
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

    self->events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, self->events,
                   &self->epcb);

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int direct_shutdown(struct sk_ops *conn, int how, int rst)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    struct linger lng = { 1, 0 };
    int ret;

    loglv(3, "direct_shutdown: shutting down %s:%u/%s",
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

    if (rst) {
        if (setsockopt(self->sfd,
                       SOL_SOCKET, SO_LINGER,&lng, sizeof(lng)) == -1) {
            perror("setsockopt()");
            abort();
        }
        if (close(self->sfd) == -1) {
            perror("close()");
            abort();
        }
        self->sfd = -1;
        return 0;
    }

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
    unsigned int new_events = enable ? (self->events | event)
                                     : (self->events & ~event);

    if (new_events != self->events) {
        int op = (self->events == 0) ? EPOLL_CTL_ADD :
                 (new_events == 0)   ? EPOLL_CTL_DEL :
                                       EPOLL_CTL_MOD;
        loop_epoll_ctl(self->loop, op, self->sfd, new_events, &self->epcb);
        self->events = new_events;
    }
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

    self->nsent += nsent;
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

    self->nread += nread;
    loglv(2, "+++ direct %zd bytes. %s:%u/%s", nread,
             self->addr, (unsigned)self->port, self->isudp ? "udp" : "tcp");

    return nread;
}

/* internal destroy function, called when refcnt reaches zero */
static void direct_destroy_internal(struct conn_direct *self)
{
    if (self->sfd != -1) {
        if (self->events)
            loop_epoll_ctl(self->loop, EPOLL_CTL_DEL, self->sfd, 0, NULL);

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
    }

    loglv(1, "Closed %s:%u (sent %zu, recieved %zu bytes)",
             self->addr, (unsigned)self->port, self->nsent, self->nread);

    free(self->addr);

    free(self);
}

/* impl for struct sk_ops :: get */
static void direct_get(struct sk_ops *conn)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    self->refcnt++;
}

/* impl for struct sk_ops :: put */
static void direct_put(struct sk_ops *conn)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    if (--self->refcnt == 0) {
        direct_destroy_internal(self);
    }
}

/* used for internal only */
static struct conn_direct *direct_create_internel(void)
{
    struct conn_direct *self;

    loglv(3, "direct_create_internel: creating a new struct conn_direct");

    if ((self = calloc(1, sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->ops.connect = &direct_connect;
    self->ops.shutdown = &direct_shutdown;
    self->ops.evctl = &direct_evctl;
    self->ops.send = &direct_send;
    self->ops.recv = &direct_recv;
    self->ops.get = &direct_get;
    self->ops.put = &direct_put;
    self->epcb.on_epoll_events = &direct_epcb_events;

    self->refcnt = 1;

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

#include "direct.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "skcomm.h"

struct conn_direct {
    struct sk_ops ops;
    struct sk_comm comm;
    void (*userev)(void *userp, unsigned int event);
    void *userp;
    int refcnt;
};

/* epoll event callback, just forward event to user */
static void direct_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct sk_comm *comm = container_of(epcb, struct sk_comm, epcb);
    struct conn_direct *self = container_of(comm, struct conn_direct, comm);
    self->userev(self->userp, events);
}

/* impl for struct sk_ops :: connect */
static int direct_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);

    skcomm_common_connect(&self->comm, addr, port);

    self->comm.events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_ADD, self->comm.sfd,
                   self->comm.events, &self->comm.epcb);

    return 0;
}

/* impl for struct sk_ops :: shutdown */
static int direct_shutdown(struct sk_ops *conn, int how, int rst)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    return skcomm_common_shutdown(&self->comm, how, rst);
}

/* impl for struct sk_ops :: evctl */
static void direct_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    return skcomm_common_evctl(&self->comm, event, enable);
}

/* impl for struct sk_ops :: send */
static ssize_t direct_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    return skcomm_common_send(&self->comm, data, size);
}

/* impl for struct sk_ops :: recv */
static ssize_t direct_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_direct *self = container_of(conn, struct conn_direct, ops);
    return skcomm_common_recv(&self->comm, data, size);
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
        skcomm_common_close(&self->comm);
        free(self);
    }
}

/* used for internal only */
static struct conn_direct *
direct_create_impl(struct loopctx *loop, void *userev, void *userp, int type)
{
    struct conn_direct *self;

    loglv(3, "direct_create_internel: creating a new struct conn_direct");

    if ((self = calloc(1, sizeof(struct conn_direct))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    self->ops.connect = &direct_connect;
    self->ops.shutdown = &direct_shutdown;
    self->ops.evctl = &direct_evctl;
    self->ops.send = &direct_send;
    self->ops.recv = &direct_recv;
    self->ops.get = &direct_get;
    self->ops.put = &direct_put;

    self->comm.epcb.on_epoll_events = &direct_epcb_events;
    self->comm.loop = loop;
    self->comm.stype = type;
    self->comm.sfd = -1;

    return self;
}

/* public function,
   create a tcp connection that will connect directly via local network */
struct sk_ops *
direct_tcp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_direct *self =
        direct_create_impl(loop, userev, userp, SOCK_STREAM);
    return &self->ops;
}

/* public function,
   create a udp connection that will connect directly via local network */
struct sk_ops *
direct_udp_create(struct loopctx *loop,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_direct *self =
        direct_create_impl(loop, userev, userp, SOCK_DGRAM);
    return &self->ops;
}

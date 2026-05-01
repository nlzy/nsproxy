#include "direct.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "skcomm.h"

struct proxy_direct {
    struct proxy ops;
    struct sk_comm comm;
    userev_fn_t *userev;
    void *userp;
    int refcnt;
};

/* epoll event callback, just forward event to user */
static void direct_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct sk_comm *comm = container_of(epcb, struct sk_comm, epcb);
    struct proxy_direct *self = container_of(comm, struct proxy_direct, comm);
    self->userev(self->userp, events);
}

/* impl for struct proxy :: shutdown */
static int direct_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skcomm_common_shutdown(&self->comm, how, rst);
}

/* impl for struct proxy :: evctl */
static int direct_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skcomm_common_evctl(&self->comm, event, enable);
}

/* impl for struct proxy :: send */
static ssize_t direct_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skcomm_common_send(&self->comm, data, size);
}

/* impl for struct proxy :: recv */
static ssize_t direct_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skcomm_common_recv(&self->comm, data, size);
}

/* impl for struct proxy :: get */
static void direct_get(struct proxy *proxy)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    self->refcnt++;
}

/* impl for struct proxy :: put */
static void direct_put(struct proxy *proxy)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    if (--self->refcnt == 0) {
        skcomm_common_close(&self->comm);
        free(self);
    }
}

/* global vtable of proxy_direct */
static const struct proxy_ops direct_ops = {
    .shutdown = &direct_shutdown,
    .evctl = &direct_evctl,
    .send = &direct_send,
    .recv = &direct_recv,
    .get = &direct_get,
    .put = &direct_put,
};

/* used for internal only */
static struct proxy_direct *
direct_create_impl(struct loopctx *loop, userev_fn_t *userev, void *userp,
                   int type, const char *addr, uint16_t port)
{
    struct proxy_direct *self;

    loglv(3, "direct_create_internel: creating a new struct conn_direct");

    if ((self = calloc(1, sizeof(struct proxy_direct))) == NULL)
        oom();

    self->ops.ops = &direct_ops;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    self->comm.epcb.on_epoll_events = &direct_epcb_events;
    self->comm.loop = loop;
    self->comm.stype = type;
    self->comm.sfd = -1;

    /* perform connect */
    skcomm_common_connect(&self->comm, addr, port);

    self->comm.events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->comm.loop, EPOLL_CTL_ADD, self->comm.sfd,
                   self->comm.events, &self->comm.epcb);

    return self;
}

/* public function,
   create a tcp connection that will connect directly via local network */
struct proxy *
direct_tcp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port)
{
    struct proxy_direct *self =
        direct_create_impl(loop, userev, userp, SOCK_STREAM, addr, port);
    return &self->ops;
}

/* public function,
   create a udp connection that will connect directly via local network */
struct proxy *
direct_udp_create(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  const char *addr, uint16_t port)
{
    struct proxy_direct *self =
        direct_create_impl(loop, userev, userp, SOCK_DGRAM, addr, port);
    return &self->ops;
}

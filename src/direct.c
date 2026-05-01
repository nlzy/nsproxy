#include "direct.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "skutils.h"

struct proxy_direct {
    struct proxy ops;

    /* loop */
    struct loopctx *loop;
    struct epcb_ops epcb;

    /* socket */
    struct skinfo info;
    int sfd;
    int stype;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;
};

/* epoll event callback, just forward event to user */
static void direct_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct proxy_direct *self = container_of(epcb, struct proxy_direct, epcb);
    self->userev(self->userp, events);
}

/* impl for struct proxy :: shutdown */
static int direct_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skutils_shutdown(&self->info, self->loop, &self->sfd, how, rst);
}

/* impl for struct proxy :: evctl */
static int direct_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skutils_evctl(&self->info, self->loop, self->sfd, &self->events,
                         &self->epcb, event, enable);
}

/* impl for struct proxy :: send */
static ssize_t direct_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skutils_send(&self->info, self->sfd, data, size);
}

/* impl for struct proxy :: recv */
static ssize_t direct_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_direct *self = container_of(proxy, struct proxy_direct, ops);
    return skutils_recv(&self->info, self->sfd, data, size);
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
        skutils_close_unreg(&self->info, self->loop, &self->sfd);
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

    /* init */
    self->ops.ops = &direct_ops;
    self->loop = loop;
    self->epcb.on_epoll_events = &direct_epcb_events;
    self->sfd = -1;
    self->stype = type;
    self->events = 0;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;

    /* perform connect */
    self->sfd = skutils_connect(&self->info, addr, port, type);
    if (self->sfd < 0) {
        free(self);
        return NULL;
    }

    self->events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, self->events,
                   &self->epcb);

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

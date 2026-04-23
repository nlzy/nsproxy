#include "dns.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "direct.h"
#include "http.h"
#include "loop.h"
#include "socks.h"

struct proxy_tcpdns;
struct tcpdns_worker;

struct proxy_tcpdns {
    struct proxy ops;
    struct loopctx *loop;

    int refcnt;

    userev_fn_t *userev;
    void *userp;

    char *addr;
    uint16_t port;

    /* user may initiate multiple queries on a single pseudo UDP connection, so
       there is multiple workers, each worker open a single TCP connection for
       a single query.
       because in DNS protocol, a single TCP connection can only handle one
       query
    */
    struct tcpdns_worker *workers;

    /* receive worker done event */
    int evfd;
    struct epcb_ops evfdepcb;

    unsigned int events;
};

struct tcpdns_worker {
    struct proxy_tcpdns *master;
    struct proxy *proxy;

    struct tcpdns_worker *prev;
    struct tcpdns_worker *next;

    char buffer[4096];
    ssize_t nbuffer;

    int done;
};

/* destory, and remove from workers list */
static void tcpdns_worker_destroy(struct tcpdns_worker *worker)
{
    struct proxy_tcpdns *master = worker->master;

    if (!worker)
        return;

    /* close connection (if present) */
    if (worker->proxy) {
        proxy_put(worker->proxy);
        worker->proxy = NULL;
    }

    /* remove from workers list */
    if (worker->next)
        worker->next->prev = worker->prev;

    if (worker->prev)
        worker->prev->next = worker->next;

    if (master->workers == worker)
        master->workers = worker->next;

    free(worker);
}

/* handle event occured in connection to DNS */
static void tcpdns_worker_handle_event(void *userp, unsigned int event)
{
    struct tcpdns_worker *worker = userp;
    struct proxy *proxy = worker->proxy;
    ssize_t nread, nsent;
    uint16_t rsz;

    if (event & (EPOLLERR | EPOLLHUP)) {
        tcpdns_worker_destroy(worker);
        return;
    }

    if (event & EPOLLIN) {
        nread = proxy_recv(proxy, worker->buffer + worker->nbuffer,
                        sizeof(worker->buffer) - worker->nbuffer);
        if (nread > 0) {
            worker->nbuffer += nread;
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nbuffer > 2) {
            memcpy(&rsz, worker->buffer, sizeof(rsz));
            rsz = be16toh(rsz);
            if (rsz + 2 == worker->nbuffer) {
                const uint64_t val = 1;
                proxy_put(proxy);
                worker->proxy = NULL;
                worker->done = 1;
                write(worker->master->evfd, &val, sizeof(val));
                return;
            }
        }
    }

    if (event & EPOLLOUT) {
        nsent = proxy_send(proxy, worker->buffer, worker->nbuffer);
        if (nsent > 0) {
            worker->nbuffer -= nsent;
            memmove(worker->buffer, worker->buffer + nsent, worker->nbuffer);
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nbuffer == 0) {
            proxy_evctl(proxy, EPOLLIN, 1);
            proxy_evctl(proxy, EPOLLOUT, 0);
        }
    }

    return;
}

/* eventfd callback, triggered when worker has data */
static void tcpdns_master_epcb_events(struct epcb_ops *epcb, unsigned events)
{
    struct proxy_tcpdns *master =
        container_of(epcb, struct proxy_tcpdns, evfdepcb);
    master->userev(master->userp, events);
}

/* empty impl for struct proxy :: shutdown */
static int tcpdns_shutdown(struct proxy *proxy, int how, int rst)
{
    return 0;
}

/* impl for struct proxy :: evctl */
static void tcpdns_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_tcpdns *master = container_of(proxy, struct proxy_tcpdns, ops);
    unsigned int new_events = enable ? (master->events | event)
                                     : (master->events & ~event);

    if (new_events != master->events) {
        int op = (master->events == 0) ? EPOLL_CTL_ADD :
                 (new_events == 0)     ? EPOLL_CTL_DEL :
                                         EPOLL_CTL_MOD;
        loop_epoll_ctl(master->loop, op, master->evfd, new_events,
                       &master->evfdepcb);
        master->events = new_events;
    }
}

/* impl for struct proxy :: send
   create a worker to handle this query
*/
static ssize_t tcpdns_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_tcpdns *master = container_of(proxy, struct proxy_tcpdns, ops);
    struct nspconf *conf = current_nspconf();
    struct tcpdns_worker *worker;
    uint16_t sizebe;

    loglv(2, "--- tcpdns %zd bytes query", size);

    if (size + 2 > sizeof(worker->buffer))
        return -E2BIG; /* query too large */

    /* init worker */
    if ((worker = calloc(1, sizeof(struct tcpdns_worker))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }
    worker->master = master;
    sizebe = htobe16(size);
    memcpy(worker->buffer, &sizebe, 2);
    memcpy(worker->buffer + 2, data, size);
    worker->nbuffer = size + 2;

    if (conf->proxytype == PROXY_SOCKS5)
        worker->proxy =
            socks_tcp_create(master->loop, &tcpdns_worker_handle_event, worker,
                             master->addr, master->port);
    else if (conf->proxytype == PROXY_HTTP)
        worker->proxy =
            http_tcp_create(master->loop, &tcpdns_worker_handle_event, worker,
                            master->addr, master->port);
    else
        worker->proxy = direct_tcp_create(master->loop,
                                          &tcpdns_worker_handle_event, worker,
                                          master->addr, master->port);

    /* insert to front of worker list */
    worker->prev = NULL;
    worker->next = master->workers;

    if (master->workers)
        master->workers->prev = worker;

    master->workers = worker;

    return size;
}

/* impl for struct proxy :: recv
   find a worker which is already got a reply, and return the reply
 */
static ssize_t tcpdns_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_tcpdns *master = container_of(proxy, struct proxy_tcpdns, ops);
    struct tcpdns_worker *worker;
    ssize_t szrepl;
    ssize_t nread;
    uint64_t val;

    if ((nread = read(master->evfd, &val, sizeof(val))) == -1)
        return -errno;

    assert(nread == sizeof(val) && val == 1);

    /* find first worker which marked done */
    for (worker = master->workers; worker; worker = worker->next) {
        if (worker->done)
            break;
    }
    if (!worker)
        return -EAGAIN; /* no worker marked done */

    /* copy answer */
    szrepl = worker->nbuffer - 2;
    assert(szrepl >= 0);
    memcpy(data, worker->buffer + 2, szrepl);

    loglv(2, "+++ tcpdns %zd bytes answer", szrepl);

    /* free */
    tcpdns_worker_destroy(worker);

    return szrepl;
}

/* internal destroy function, called when refcnt reaches zero */
static void tcpdns_destroy_internal(struct proxy_tcpdns *master)
{
    loglv(3, "tcpdns_destroy_internal: destroying tcpdns master");

    while (master->workers)
        tcpdns_worker_destroy(master->workers);

    if (master->evfd != -1)
        if (close(master->evfd) == -1) {
            perror("close()");
            abort();
        }

    free(master->addr);
    free(master);
}

/* impl for struct proxy :: get */
static void tcpdns_get(struct proxy *proxy)
{
    struct proxy_tcpdns *master = container_of(proxy, struct proxy_tcpdns, ops);
    master->refcnt++;
}

/* impl for struct proxy :: put */
static void tcpdns_put(struct proxy *proxy)
{
    struct proxy_tcpdns *master = container_of(proxy, struct proxy_tcpdns, ops);
    if (--master->refcnt == 0) {
        tcpdns_destroy_internal(master);
    }
}

/* global vtable of proxy_tcpdns */
static const struct proxy_ops dns_ops = {
    .shutdown = &tcpdns_shutdown,
    .evctl = &tcpdns_evctl,
    .send = &tcpdns_send,
    .recv = &tcpdns_recv,
    .get = &tcpdns_get,
    .put = &tcpdns_put,
};

/* create a pseudo udp connection
   used for handle DNS request represented in datagrams and forward to a
   TCP nameserver */
struct proxy *tcpdns_create(struct loopctx *loop, userev_fn_t *userev,
                             void *userp, const char *addr, uint16_t port)
{
    struct proxy_tcpdns *master;

    loglv(3, "tcpdns_create: creating a new struct conn_tcpdns");

    if ((master = calloc(1, sizeof(struct proxy_tcpdns))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    master->ops.ops = &dns_ops;
    master->evfdepcb.on_epoll_events = &tcpdns_master_epcb_events;

    master->refcnt = 1;
    master->userev = userev;
    master->userp = userp;

    master->loop = loop;

    /* perform connect */
    if (strlen(addr) >= SERVNAME_MAXLEN) {
        free(master);
        return NULL;
    }

    master->addr = strdup(addr);
    master->port = port;

    if (master->evfd == -1) {
        master->evfd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
        if (master->evfd  == -1) {
            perror("eventfd()");
            abort();
        }
    }

    master->events = EPOLLOUT | EPOLLIN;
    loop_epoll_ctl(master->loop, EPOLL_CTL_ADD, master->evfd, master->events,
                   &master->evfdepcb);

    master->events = 0;
    master->evfd = -1;

    return &master->ops;
}

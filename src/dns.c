#include "dns.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <sys/epoll.h>

#include "direct.h"
#include "http.h"
#include "loop.h"
#include "socks.h"

struct conn_tcpdns;
struct conn_tcpdns_worker;

struct conn_tcpdns {
    struct sk_ops ops;
    struct loopctx *loop;

    int refcnt;

    void (*userev)(void *userp, unsigned int event);
    void *userp;

    char *addr;
    uint16_t port;

    /* user may initiate multiple queries on a single pseudo UDP connection, so
       there is multiple workers, each worker open a single TCP connection for a
       single query.
       because in DNS protocol, a single TCP connection can only handle one
       query
    */
    struct conn_tcpdns_worker *workers;
};

struct conn_tcpdns_worker {
    struct conn_tcpdns *master;
    struct sk_ops *proxy;

    struct conn_tcpdns_worker *prev;
    struct conn_tcpdns_worker *next;

    char buffer[4096];
    ssize_t nbuffer;

    int done;
};

/* destory, and remove from workers list */
static void tcpdns_worker_destroy(struct conn_tcpdns_worker *worker)
{
    struct conn_tcpdns *master = worker->master;

    if (!worker)
        return;

    /* close connection (if present) */
    if (worker->proxy) {
        worker->proxy->put(worker->proxy);
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
    struct conn_tcpdns_worker *worker = userp;
    struct sk_ops *proxy = worker->proxy;
    ssize_t nread, nsent;
    uint16_t rsz;

    if (event & (EPOLLERR | EPOLLHUP)) {
        tcpdns_worker_destroy(worker);
        return;
    }

    if (event & EPOLLIN) {
        nread = proxy->recv(proxy, worker->buffer + worker->nbuffer,
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
                proxy->put(proxy);
                worker->proxy = NULL;
                worker->done = 1;
                worker->master->userev(worker->master->userp, EPOLLIN);
                return;
            }
        }
    }

    if (event & EPOLLOUT) {
        nsent = proxy->send(proxy, worker->buffer, worker->nbuffer);
        if (nsent > 0) {
            worker->nbuffer -= nsent;
            memmove(worker->buffer, worker->buffer + nsent, worker->nbuffer);
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nbuffer == 0) {
            proxy->evctl(proxy, EPOLLIN, 1);
            proxy->evctl(proxy, EPOLLOUT, 0);
        }
    }

    return;
};

/* impl for struct sk_ops :: connect
   just copy the address of nameserver, actual connecting is delayed until any
   queries started.
*/
static int tcpdns_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);

    if (strlen(addr) >= 128)
        return -1;

    master->addr = strdup(addr);
    master->port = port;

    return 0;
}

/* empty impl for struct sk_ops :: shutdown */
static int tcpdns_shutdown(struct sk_ops *conn, int how, int rst)
{
    return 0;
}

/* empty impl for struct sk_ops :: evctl */
static void tcpdns_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    return;
}

/* impl for struct sk_ops :: send
   create a worker to handle this query
*/
static ssize_t tcpdns_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    struct nspconf *conf = current_nspconf();
    struct conn_tcpdns_worker *worker;
    uint16_t sizebe;

    loglv(2, "--- tcpdns %zd bytes query", size);

    if (size + 2 > sizeof(worker->buffer))
        return -E2BIG; /* query too large */

    /* init worker */
    if ((worker = calloc(1, sizeof(struct conn_tcpdns_worker))) == NULL) {
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
            socks_tcp_create(master->loop, &tcpdns_worker_handle_event, worker);
    else if (conf->proxytype == PROXY_HTTP)
        worker->proxy =
            http_tcp_create(master->loop, &tcpdns_worker_handle_event, worker);
    else
        worker->proxy = direct_tcp_create(master->loop,
                                          &tcpdns_worker_handle_event, worker);

    worker->proxy->connect(worker->proxy, master->addr, master->port);

    /* insert to front of worker list */
    worker->prev = NULL;
    worker->next = master->workers;

    if (master->workers)
        master->workers->prev = worker;

    master->workers = worker;

    return size;
}

/* impl for struct sk_ops :: recv
   find a worker which is already got a reply, and return the reply
 */
static ssize_t tcpdns_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    struct conn_tcpdns_worker *worker;
    ssize_t n;

    /* find first worker which marked done */
    for (worker = master->workers; worker; worker = worker->next) {
        if (worker->done)
            break;
    }
    if (!worker)
        return -EAGAIN; /* no worker marked done */

    /* copy answer */
    n = worker->nbuffer - 2;
    memcpy(data, worker->buffer + 2, n);

    loglv(2, "+++ tcpdns %zd bytes answer", n);

    /* free */
    tcpdns_worker_destroy(worker);

    return n;
}

/* internal destroy function, called when refcnt reaches zero */
static void tcpdns_destroy_internal(struct conn_tcpdns *master)
{
    loglv(3, "tcpdns_destroy_internal: destroying tcpdns master");

    while (master->workers)
        tcpdns_worker_destroy(master->workers);

    free(master->addr);
    free(master);
}

/* impl for struct sk_ops :: get */
static void tcpdns_get(struct sk_ops *conn)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    master->refcnt++;
}

/* impl for struct sk_ops :: put */
static void tcpdns_put(struct sk_ops *conn)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    if (--master->refcnt == 0) {
        tcpdns_destroy_internal(master);
    }
}

/* create a pseudo udp connection
   used for handle DNS request represented in datagrams and forward to a
   TCP nameserver */
struct sk_ops *tcpdns_create(struct loopctx *loop,
                             void (*userev)(void *userp, unsigned int event),
                             void *userp)
{
    struct conn_tcpdns *master;

    loglv(3, "tcpdns_create: creating a new struct conn_tcpdns");

    if ((master = calloc(1, sizeof(struct conn_tcpdns))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    master->ops.connect = &tcpdns_connect;
    master->ops.shutdown = &tcpdns_shutdown;
    master->ops.evctl = &tcpdns_evctl;
    master->ops.send = &tcpdns_send;
    master->ops.recv = &tcpdns_recv;
    master->ops.get = &tcpdns_get;
    master->ops.put = &tcpdns_put;

    master->refcnt = 1;
    master->userev = userev;
    master->userp = userp;

    master->loop = loop;

    return &master->ops;
}

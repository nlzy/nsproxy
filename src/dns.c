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
    struct conn_tcpdns_worker *workers[4];
    size_t nworker;
};

struct conn_tcpdns_worker {
    struct conn_tcpdns *master;
    struct sk_ops *proxy;

    char sndbuf[2048];
    ssize_t nsndbuf;

    char rcvbuf[2048];
    ssize_t nrcvbuf;

    int done;
};

/* destory, and remove from workers list */
void tcpdns_worker_destroy(struct conn_tcpdns_worker *worker)
{
    struct conn_tcpdns *master = worker->master;
    size_t i;

    /* close connection (if present) */
    if (worker->proxy) {
        worker->proxy->destroy(worker->proxy);
        worker->proxy = NULL;
    }

    /* remove this worker from workers list */
    for (i = 0; i < master->nworker; i++) {
        if (master->workers[i] == worker) {
            break;
        }
    }
    if (i != master->nworker) {
        master->workers[i] = master->workers[master->nworker - 1];
        master->nworker--;
    }

    /* gone */
    free(worker);
}

/* handle event occured in connection to DNS */
void tcpdns_worker_handle_event(void *userp, unsigned int event)
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
        nread = proxy->recv(proxy, worker->rcvbuf + worker->nrcvbuf,
                            sizeof(worker->rcvbuf) - worker->nrcvbuf);
        if (nread > 0) {
            worker->nrcvbuf += nread;
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nrcvbuf > 2) {
            memcpy(&rsz, worker->rcvbuf, sizeof(rsz));
            rsz = be16toh(rsz);
            if (rsz + 2 == worker->nrcvbuf) {
                proxy->destroy(proxy);
                worker->proxy = NULL;
                worker->done = 1;
                worker->master->userev(worker->master->userp, EPOLLIN);
                return;
            }
        }
    }

    if (event & EPOLLOUT) {
        nsent = proxy->send(proxy, worker->sndbuf, worker->nsndbuf);
        if (nsent > 0) {
            worker->nsndbuf -= nsent;
            memmove(worker->sndbuf, worker->sndbuf + nsent, worker->nsndbuf);
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nsndbuf == 0) {
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
int tcpdns_connect(struct sk_ops *conn, const char *addr, uint16_t port)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);

    if (strlen(addr) >= 512)
        return -1;

    master->addr = strdup(addr);
    master->port = port;

    return 0;
}

/* empty impl for struct sk_ops :: shutdown */
int tcpdns_shutdown(struct sk_ops *conn, int how)
{
    return 0;
}

/* empty impl for struct sk_ops :: evctl */
void tcpdns_evctl(struct sk_ops *conn, unsigned int event, int enable)
{
    return;
}

/* impl for struct sk_ops :: send
   create a worker to handle this query
*/
ssize_t tcpdns_send(struct sk_ops *conn, const char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    struct conn_tcpdns_worker *worker;
    uint16_t sizebe;

    if (master->nworker == arraysizeof(master->workers))
        return -EAGAIN; /* no available worker */

    if (size + 2 > sizeof(worker->sndbuf))
        return -EAGAIN; /* query too large */

    /* init worker */
    if ((worker = calloc(1, sizeof(struct conn_tcpdns_worker))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }
    worker->master = master;
    sizebe = htobe16(size);
    memcpy(worker->sndbuf, &sizebe, 2);
    memcpy(worker->sndbuf + 2, data, size);
    worker->nsndbuf = size + 2;

    if (loop_conf(master->loop)->proxytype == PROXY_SOCKS5)
        worker->proxy =
            socks_tcp_create(master->loop, &tcpdns_worker_handle_event, worker);
    else if (loop_conf(master->loop)->proxytype == PROXY_HTTP)
        worker->proxy =
            http_tcp_create(master->loop, &tcpdns_worker_handle_event, worker);
    else
        abort();

    worker->proxy->connect(worker->proxy, master->addr, master->port);

    /* add to workers list */
    master->workers[master->nworker] = worker;
    master->nworker++;

    return size;
}

/* impl for struct sk_ops :: recv
   find a worker which is already got a reply, and return the reply
 */
ssize_t tcpdns_recv(struct sk_ops *conn, char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    struct conn_tcpdns_worker *worker = NULL;
    size_t i;
    ssize_t n;

    /* find first worker which marked done */
    for (i = 0; i < master->nworker; i++) {
        if (master->workers[i]->done) {
            worker = master->workers[i];
            break;
        }
    }
    if (!worker)
        return -EAGAIN; /* no worker done */

    /* copy answer */
    n = worker->nrcvbuf - 2;
    memcpy(data, worker->rcvbuf + 2, n);

    /* free */
    tcpdns_worker_destroy(worker);

    return n;
}

/* impl for struct sk_ops :: destory */
void tcpdns_destroy(struct sk_ops *conn)
{
    struct conn_tcpdns *master = container_of(conn, struct conn_tcpdns, ops);
    struct conn_tcpdns_worker *worker;
    size_t i;

    for (i = 0; i < master->nworker; i++) {
        worker = master->workers[i];
        if (worker->proxy)
            worker->proxy->destroy(worker->proxy);
        free(worker);
    }

    free(master->addr);
    free(master);
}

/* create a pseudo udp connection
   used for handle DNS request represented in datagrams and forward to a
   TCP nameserver */
struct sk_ops *tcpdns_create(struct loopctx *loop,
                             void (*userev)(void *userp, unsigned int event),
                             void *userp)
{
    struct conn_tcpdns *master;

    if ((master = calloc(1, sizeof(struct conn_tcpdns))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    master->ops.connect = &tcpdns_connect;
    master->ops.shutdown = &tcpdns_shutdown;
    master->ops.evctl = &tcpdns_evctl;
    master->ops.send = &tcpdns_send;
    master->ops.recv = &tcpdns_recv;
    master->ops.destroy = &tcpdns_destroy;

    master->userev = userev;
    master->userp = userp;

    master->loop = loop;

    return &master->ops;
}

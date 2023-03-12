#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>

#include "direct.h"
#include "http.h"
#include "loop.h"
#include "socks.h"

#define DNSH_RCODE_NOERROR  0
#define DNSH_RCODE_FORMERR  1
#define DNSH_RCODE_SERVFAIL 2
#define DNSH_RCODE_NXDOMAIN 3
#define DNSH_RCODE_NOTIMP   4
#define DNSH_RCODE_REFUSED  5
#define DNSH_RCODE_YXDOMAIN 6
#define DNSH_RCODE_XRRSET   7
#define DNSH_RCODE_NOTAUTH  8
#define DNSH_RCODE_NOTZONE  9

struct dnshdr {
    uint16_t id;
    union {
        struct {
#if __BYTE_ORDER__ == __BIG_ENDIAN__
            uint16_t qr : 1;
            uint16_t opcode : 4;
            uint16_t aa : 1;
            uint16_t tc : 1;
            uint16_t rd : 1;
            uint16_t ra : 1;
            uint16_t zero : 3;
            uint16_t rcode : 4;
#else
            uint16_t rd : 1;
            uint16_t tc : 1;
            uint16_t aa : 1;
            uint16_t opcode : 4;
            uint16_t qr : 1;
            uint16_t rcode : 4;
            uint16_t zero : 3;
            uint16_t ra : 1;
#endif
        } flag;
        uint16_t flags;
    };
    uint16_t numquestions;
    uint16_t numanswers;
    uint16_t numauthrr;
    uint16_t numextrarr;
};

struct dnsquery {
    char name[256];
    uint16_t type;
    uint16_t class;
};

struct dnsanswer {
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rl;
    char resource[256];
};

ssize_t dns_hdr_put(char *buffer, size_t size, const struct dnshdr *hdr)
{
    struct dnshdr hdrbe = {
        .id = htobe16(hdr->id),
        .flags = hdr->flags,
        .numquestions = htobe16(hdr->numquestions),
        .numanswers = htobe16(hdr->numanswers),
        .numauthrr = htobe16(hdr->numauthrr),
        .numextrarr = htobe16(hdr->numextrarr),
    };

    if (sizeof(struct dnshdr) > size)
        return -1;

    memcpy(buffer, &hdrbe, sizeof(hdrbe));
    return sizeof(hdrbe);
}

ssize_t dns_hdr_get(struct dnshdr *hdr, const char *buffer, size_t size)
{
    if (sizeof(struct dnshdr) > size)
        return -1;

    memcpy(hdr, buffer, sizeof(struct dnshdr));

    hdr->id = be16toh(hdr->id);
    hdr->numquestions = be16toh(hdr->numquestions);
    hdr->numanswers = be16toh(hdr->numanswers);
    hdr->numauthrr = be16toh(hdr->numauthrr);
    hdr->numextrarr = be16toh(hdr->numextrarr);

    return sizeof(struct dnshdr);
}

ssize_t dns_query_put(char *buffer, size_t size, const struct dnsquery *q)
{
    char *cur = buffer;
    size_t namelen = strlen(q->name) + 1;
    uint16_t typebe = htobe16(q->type);
    uint16_t classbe = htobe16(q->class);

    if (namelen + sizeof(q->type) + sizeof(q->class) > size)
        return -1;

    /* put name field */
    memcpy(cur, q->name, namelen);
    cur += namelen;

    /* put type field */
    memcpy(cur, &typebe, sizeof(q->type));
    cur += sizeof(q->type);

    /* put class field */
    memcpy(cur, &classbe, sizeof(q->class));
    cur += sizeof(q->class);

    return cur - buffer;
}

ssize_t dns_query_get(struct dnsquery *q, const char *buffer, size_t size)
{
    const char *cur = buffer;
    uint8_t c;

    if (size == 0)
        return -1;

    /* traverse name field */
    for (;;) {
        c = *cur % 64;
        cur += 1;
        if (c == 0)
            break;
        if ((cur - buffer) + c + 1 > (ssize_t)size)
            return -1;
        cur += c;
    }
    if (cur - buffer > (ssize_t)sizeof(q->name))
        return -1; /* name too long */

    /* copy name field */
    memcpy(q->name, buffer, cur - buffer);

    /* copy type and class fields */
    if (cur - buffer + sizeof(q->type) + sizeof(q->class) > size)
        return -1;

    memcpy(&q->type, cur, sizeof(q->type));
    cur += sizeof(q->type);

    memcpy(&q->class, cur, sizeof(q->class));
    cur += sizeof(q->class);

    q->type = be16toh(q->type);
    q->class = be16toh(q->class);

    return cur - buffer;
}

ssize_t dns_answer_put(char *buffer, size_t size, const struct dnsanswer *ans)
{
    char *cur = buffer;
    size_t namelen = strlen(ans->name) + 1;
    uint16_t typebe = htobe16(ans->type);
    uint16_t classbe = htobe16(ans->class);
    uint32_t ttlbe = htobe32(ans->ttl);
    uint16_t rlbe = htobe16(ans->rl);

    if (namelen + sizeof(ans->type) + sizeof(ans->class) + sizeof(ans->ttl) +
            sizeof(ans->rl) + ans->rl >
        size) {
        return -1;
    }

    /* put name field */
    memcpy(cur, ans->name, namelen);
    cur += namelen;

    /* put type field */
    memcpy(cur, &typebe, sizeof(ans->type));
    cur += sizeof(ans->type);

    /* put class field */
    memcpy(cur, &classbe, sizeof(ans->class));
    cur += sizeof(ans->class);

    /* put ttl field */
    memcpy(cur, &ttlbe, sizeof(ans->ttl));
    cur += sizeof(ans->ttl);

    /* put rl field */
    memcpy(cur, &rlbe, sizeof(ans->rl));
    cur += sizeof(ans->rl);

    /* put resource field */
    memcpy(cur, ans->resource, ans->rl);
    cur += ans->rl;

    return cur - buffer;
}

ssize_t dns_answer_get(struct dnsanswer *ans, const char *buffer, size_t size)
{
    const char *cur = buffer;
    uint8_t c;

    if (size == 0)
        return -1;

    /* traverse name field */
    for (;;) {
        c = *cur % 64;
        cur += 1;
        if (c == 0)
            break;
        if ((cur - buffer) + c + 1 > (ssize_t)size)
            return -1;
        cur += c;
    }
    if (cur - buffer > (ssize_t)sizeof(ans->name))
        return -1; /* name too long */

    /* copy name field */
    memcpy(ans->name, buffer, cur - buffer);

    /* copy type / class / ttl / rl fields */
    if (cur - buffer + sizeof(ans->type) + sizeof(ans->class) +
            sizeof(ans->ttl) + sizeof(ans->rl) >
        size)
        return -1;

    memcpy(&ans->type, cur, sizeof(ans->type));
    cur += sizeof(ans->type);

    memcpy(&ans->class, cur, sizeof(ans->class));
    cur += sizeof(ans->class);

    memcpy(&ans->ttl, cur, sizeof(ans->ttl));
    cur += sizeof(ans->ttl);

    memcpy(&ans->rl, cur, sizeof(ans->rl));
    cur += sizeof(ans->rl);

    ans->type = be16toh(ans->type);
    ans->class = be16toh(ans->class);
    ans->ttl = be32toh(ans->ttl);
    ans->rl = be16toh(ans->rl);

    /* copy resource */
    if (cur - buffer + ans->rl > (ssize_t)size)
        return -1;
    if (ans->rl > sizeof(ans->resource))
        return -1;
    memcpy(ans->resource, cur, ans->rl);
    cur += ans->rl;

    return cur - buffer;
}

struct conn_fakedns {
    struct sk_ops ops;
    void (*userev)(void *userp, unsigned int event);
    void *userp;
    struct dnshdr hdr;
    struct dnsquery query;
    struct context_loop *ctx;
    uint8_t rcode;
};

int fakedns_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    return 0;
}

int fakedns_shutdown(struct sk_ops *handle, int how)
{
    return 0;
}

void fakedns_evctl(struct sk_ops *handle, unsigned int event, int enable)
{
    return;
}

ssize_t fakedns_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_fakedns *h = container_of(handle, struct conn_fakedns, ops);
    struct dnsanswer ans;
    size_t offset = 0;
    size_t i;
    ssize_t ret;

    /* copy and check dnshdr */
    if ((ret = dns_hdr_get(&h->hdr, data, size)) == -1)
        return -EAGAIN;
    offset += ret;

    /* copy and check dnsquery */
    if ((ret = dns_query_get(&h->query, data + offset, size)) == -1)
        return -EAGAIN;
    offset += ret;

    /* copy and check extarr */
    for (i = 0; i < h->hdr.numextrarr; i++) {
        if ((ret = dns_answer_get(&ans, data + offset, size)) == -1)
            return -EAGAIN;
        offset += ret;
    }

    /* length check */
    if (offset != size)
        return -EAGAIN;

    if (h->hdr.flag.qr != 0)
        h->rcode = DNSH_RCODE_FORMERR; /* not query */

    else if (h->hdr.flag.opcode != 0)
        h->rcode = DNSH_RCODE_FORMERR; /* not standard query */

    else if (h->hdr.numquestions != 1)
        h->rcode = DNSH_RCODE_FORMERR; /* not a single query */

    else if (h->hdr.numanswers != 0 || h->hdr.numauthrr != 0)
        h->rcode = DNSH_RCODE_FORMERR; /* malformed query */

    else if (h->query.class != 1 || h->query.type != 1)
        h->rcode = DNSH_RCODE_NOTIMP; /* not IPv4 A query */

    else
        h->rcode = DNSH_RCODE_NOERROR;

    h->userev(h->userp, EPOLLIN);

    return size;
}

ssize_t fakedns_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_fakedns *h = container_of(handle, struct conn_fakedns, ops);

    struct dnshdr hdr;
    struct dnsquery query;
    struct dnsanswer answer;
    size_t offset = 0;
    ssize_t ret;
    struct in_addr fakeip;

    /* fill hdr */
    memset(&hdr, 0, sizeof(hdr));
    hdr.flag.qr = 1;
    hdr.flag.rd = 1;
    hdr.flag.ra = 1;
    hdr.flag.rcode = h->rcode;
    hdr.id = h->hdr.id;
    hdr.numquestions = 1;
    hdr.numanswers = h->rcode == DNSH_RCODE_NOERROR ? 1 : 0;
    if ((ret = dns_hdr_put(data + offset, size, &hdr)) == -1)
        return -EAGAIN;
    offset += ret;

    /* fill query */
    memcpy(&query, &h->query, sizeof(query));
    if ((ret = dns_query_put(data + offset, size, &query)) == -1)
        return -EAGAIN;
    offset += ret;

    /* if an error occured, don't send answer */
    if (h->rcode != DNSH_RCODE_NOERROR) {
        return offset;
    }

    /* fill answer */
    answer.type = 1;
    answer.class = 1;
    answer.ttl = 600;
    answer.rl = 4;
    strcpy(answer.name, query.name);

    inet_aton("192.168.48.4", &fakeip);
    memcpy(answer.resource, &fakeip, sizeof(fakeip));

    if ((ret = dns_answer_put(data + offset, size, &answer)) == -1)
        return -EAGAIN;
    offset += ret;

    return offset;
}

void fakedns_destroy(struct sk_ops *handle)
{
    struct conn_fakedns *h = container_of(handle, struct conn_fakedns, ops);
    free(h);
}

int fakedns_create(struct sk_ops **handle, struct context_loop *ctx,
                   void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_fakedns *h;

    if ((h = malloc(sizeof(struct conn_fakedns))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    h->ops.connect = &fakedns_connect;
    h->ops.shutdown = &fakedns_shutdown;
    h->ops.evctl = &fakedns_evctl;
    h->ops.send = &fakedns_send;
    h->ops.recv = &fakedns_recv;
    h->ops.destroy = &fakedns_destroy;

    h->userev = userev;
    h->userp = userp;

    h->ctx = ctx;

    *handle = &h->ops;
    return 0;
}

void dns_tmr(void)
{
    return;
}

struct conn_tcpdns;
struct conn_tcpdns_worker;

struct conn_tcpdns {
    struct sk_ops ops;
    void (*userev)(void *userp, unsigned int event);
    void *userp;
    struct context_loop *ctx;
    struct conn_tcpdns_worker *workers[16];
    size_t nworker;
    char addr[512];
    uint16_t port;
};

struct conn_tcpdns_worker {
    struct sk_ops *conn;
    struct conn_tcpdns *master;

    char sndbuf[2048];
    ssize_t nsndbuf;

    char rcvbuf[2048];
    ssize_t nrcvbuf;

    int done;
};

void tcpdns_worker_destroy(struct conn_tcpdns_worker *worker)
{
    struct conn_tcpdns *master = worker->master;
    size_t i;

    /* close connection (if present) */
    if (worker->conn) {
        worker->conn->destroy(worker->conn);
        worker->conn = NULL;
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

void tcpdns_worker_handle_event(void *userp, unsigned int event)
{
    struct conn_tcpdns_worker *worker = userp;
    struct sk_ops *conn = worker->conn;
    ssize_t nread, nsent;
    uint16_t rsz;

    if (event & (EPOLLERR | EPOLLHUP)) {
        tcpdns_worker_destroy(worker);
        return;
    }

    if (event & EPOLLIN) {
        nread = conn->recv(conn, worker->rcvbuf + worker->nrcvbuf,
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
                conn->destroy(conn);
                worker->conn = NULL;
                worker->done = 1;
                worker->master->userev(worker->master->userp, EPOLLIN);
                return;
            }
        }
    }

    if (event & EPOLLOUT) {
        nsent = conn->send(conn, worker->sndbuf, worker->nsndbuf);
        if (nsent > 0) {
            worker->nsndbuf -= nsent;
            memmove(worker->sndbuf, worker->sndbuf + nsent, worker->nsndbuf);
        } else {
            tcpdns_worker_destroy(worker);
            return;
        }
        if (worker->nsndbuf == 0) {
            conn->evctl(conn, EPOLLIN, 1);
            conn->evctl(conn, EPOLLOUT, 0);
        }
    }

    return;
};

int tcpdns_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_tcpdns *master = container_of(handle, struct conn_tcpdns, ops);

    if (strlen(addr) >= 512)
        return -1;

    strcpy(master->addr, addr);
    master->port = port;

    return 0;
}

int tcpdns_shutdown(struct sk_ops *handle, int how)
{
    return 0;
}

void tcpdns_evctl(struct sk_ops *handle, unsigned int event, int enable)
{
    return;
}

ssize_t tcpdns_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(handle, struct conn_tcpdns, ops);
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

    if (loop_conf(master->ctx)->proxytype == PROXY_SOCKS5)
        socks_tcp_create(&worker->conn, master->ctx,
                         &tcpdns_worker_handle_event, worker);
    else if (loop_conf(master->ctx)->proxytype == PROXY_HTTP)
        http_tcp_create(&worker->conn, master->ctx, &tcpdns_worker_handle_event,
                        worker);
    else
        abort();

    worker->conn->connect(worker->conn, master->addr, master->port);

    /* add to workers list */
    master->workers[master->nworker] = worker;
    master->nworker++;

    return size;
}

ssize_t tcpdns_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_tcpdns *master = container_of(handle, struct conn_tcpdns, ops);
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

void tcpdns_destroy(struct sk_ops *handle)
{
    struct conn_tcpdns *master = container_of(handle, struct conn_tcpdns, ops);

    while (master->nworker) {
        tcpdns_worker_destroy(master->workers[0]);
    }

    free(master);
}

int tcpdns_create(struct sk_ops **handle, struct context_loop *ctx,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_tcpdns *master;

    if ((master = calloc(1, sizeof(struct conn_tcpdns))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
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

    master->ctx = ctx;

    *handle = &master->ops;
    return 0;
}

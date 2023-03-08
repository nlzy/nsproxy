#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "direct.h"
#include "loop.h"
#include "lwip/ip4_addr.h"
#include "socks.h"

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
    uint8_t c, t;

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
    uint8_t c, t;

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
};

int fakedns_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    return 0;
}

int fakedns_shutdown(struct sk_ops *handle, int how)
{
    return 0;
}

void fakedns_evctl(struct sk_ops *handle, uint32_t event, int enable)
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

    if (h->hdr.flag.qr != 0)
        return -EAGAIN; /* not query */

    if (h->hdr.flag.opcode != 0)
        return -EAGAIN; /* not standard query */

    if (h->hdr.numquestions != 1)
        return -EAGAIN; /* not a single query */

    if (h->hdr.numanswers != 0 || h->hdr.numauthrr != 0)
        return -EAGAIN; /* malformed query */

    /* copy and check dnsquery */
    if ((ret = dns_query_get(&h->query, data + offset, size)) == -1)
        return -EAGAIN;
    offset += ret;

    /* TODO: IPv6 AAAA query */
    if (h->query.type != 1 || h->query.class != 1)
        return -EAGAIN; /* not IPv4 A query */

    for (i = 0; i < h->hdr.numextrarr; i++) {
        if ((ret = dns_answer_get(&ans, data + offset, size)) == -1)
            return -EAGAIN;
        offset += ret;
    }

    /* length check */
    if (offset != size)
        return -EAGAIN;

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
    struct ip4_addr fakeip;

    /* prepare hdr */
    memset(&hdr, 0, sizeof(hdr));
    hdr.flag.qr = 1;
    hdr.flag.rd = 1;
    hdr.flag.ra = 1;
    hdr.id = h->hdr.id;
    hdr.numquestions = 1;
    hdr.numanswers = 1;

    /* prepare query */
    memcpy(&query, &h->query, sizeof(query));

    /* prepare answer */
    answer.type = 1;
    answer.class = 1;
    answer.ttl = 600;
    answer.rl = 4;
    strcpy(answer.name, query.name);
    ip4addr_aton("192.168.48.4", &fakeip);
    memcpy(answer.resource, &fakeip, sizeof(fakeip));

    if ((ret = dns_hdr_put(data + offset, size, &hdr)) == -1)
        return -EAGAIN;
    offset += ret;

    if ((ret = dns_query_put(data + offset, size, &query)) == -1)
        return -EAGAIN;
    offset += ret;

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

struct conn_tcpdns {
    struct sk_ops ops;
    void (*userev)(void *userp, unsigned int event);
    void *userp;
    struct context_loop *ctx;
    struct sk_ops *upstream;
    char sndbuf[2048];
    ssize_t nsndbuf;
    char rcvbuf[2048];
    ssize_t nrcvbuf;
    int done;
};

void tcpdns_handle_event(void *userp, unsigned int event)
{
    struct conn_tcpdns *h = userp;
    struct sk_ops *upstream = h->upstream;
    ssize_t nsent, nread;
    uint16_t rsz;

    if (event & EPOLLERR) {
        h->userev(h->userp, EPOLLERR);
        return;
    }

    if (event & EPOLLIN) {
        nread = upstream->recv(upstream, h->rcvbuf + h->nrcvbuf,
                               sizeof(h->rcvbuf) - h->nrcvbuf);
        if (nread > 0) {
            h->nrcvbuf += nread;
            if (h->nrcvbuf > 2) {
                memcpy(&rsz, h->rcvbuf, sizeof(rsz));
                rsz = be16toh(rsz);
                if (rsz + 2 == h->nrcvbuf) {
                    h->done = 1;
                    h->userev(h->userp, EPOLLIN);
                    h->userev(h->userp, EPOLLHUP);
                    return;
                }
            }
        } else if (nread == 0) {
            h->userev(h->userp, EPOLLERR);
            return;
        } else if (nread == -EAGAIN) {
            upstream->evctl(upstream, EPOLLIN, 1);
        } else {
            h->userev(h->userp, EPOLLERR);
            return;
        }
    }

    if (event & EPOLLOUT) {
        nsent = upstream->send(upstream, h->sndbuf, h->nsndbuf);
        if (nsent > 0 && nsent == h->nsndbuf) {
            h->nsndbuf = 0;
            upstream->evctl(upstream, EPOLLOUT, 0);
            upstream->evctl(upstream, EPOLLIN, 1);
        } else if (nsent > 0) {
            h->nsndbuf -= nsent;
            memmove(h->sndbuf, h->sndbuf + nsent, h->nsndbuf);
        } else if (nsent == -EAGAIN) {
            upstream->evctl(upstream, EPOLLOUT, 1);
        } else {
            h->userev(h->userp, EPOLLERR);
            return;
        }
    }

    if (event & EPOLLHUP) {
        h->userev(h->userp, EPOLLHUP);
    }
}

int tcpdns_connect(struct sk_ops *handle, const char *addr, uint16_t port)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    int ret = h->upstream->connect(h->upstream, addr, port);

    h->upstream->evctl(h->upstream, EPOLLIN | EPOLLOUT, 0);

    return ret;
}

int tcpdns_shutdown(struct sk_ops *handle, int how)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    return h->upstream->shutdown(h->upstream, how);
}

void tcpdns_evctl(struct sk_ops *handle, uint32_t event, int enable)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    return;
}

ssize_t tcpdns_send(struct sk_ops *handle, const char *data, size_t size)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    uint16_t sizebe;

    if (h->nsndbuf)
        return -EAGAIN;

    if (size + 2 > sizeof(h->sndbuf))
        return -EAGAIN;

    sizebe = htobe16(size);
    memcpy(h->sndbuf, &sizebe, 2);

    memcpy(h->sndbuf + 2, data, size);

    h->nsndbuf = size + 2;

    h->upstream->evctl(h->upstream, EPOLLOUT, 1);

    return size;
}

ssize_t tcpdns_recv(struct sk_ops *handle, char *data, size_t size)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    size_t n = h->nrcvbuf - 2;

    if (size < n)
        return -EAGAIN;

    if (!h->done)
        return -EAGAIN;

    if (!h->nrcvbuf)
        return -EAGAIN;

    memcpy(data, h->rcvbuf + 2, n);
    h->nrcvbuf = 0;

    return n;
}

void tcpdns_destroy(struct sk_ops *handle)
{
    struct conn_tcpdns *h = container_of(handle, struct conn_tcpdns, ops);
    if (h->upstream)
        h->upstream->destroy(h->upstream);
    free(h);
}

int tcpdns_create(struct sk_ops **handle, struct context_loop *ctx,
                  void (*userev)(void *userp, unsigned int event), void *userp)
{
    struct conn_tcpdns *h;

    if ((h = calloc(1, sizeof(struct conn_tcpdns))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    h->ops.connect = &tcpdns_connect;
    h->ops.shutdown = &tcpdns_shutdown;
    h->ops.evctl = &tcpdns_evctl;
    h->ops.send = &tcpdns_send;
    h->ops.recv = &tcpdns_recv;
    h->ops.destroy = &tcpdns_destroy;

    h->userev = userev;
    h->userp = userp;

    h->ctx = ctx;

    socks_tcp_create(&h->upstream, ctx, &tcpdns_handle_event, h);

    *handle = &h->ops;
    return 0;
}

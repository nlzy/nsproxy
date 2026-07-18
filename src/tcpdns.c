/*
 * Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "tcpdns.h"

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "direct.h"
#include "http.h"
#include "loop.h"
#include "skutils.h"
#include "socks.h"

struct proxy_tcpdns;
struct tcpdns_worker;

struct proxy_tcpdns {
    struct proxy ops;

    /* loop */
    struct loopctx *loop;
    struct epcb_ops evfdepcb;

    /* eventfd, receive worker done event */
    int evfd;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;

    /* Unfortunately, not all DNS servers support connection reuse (RFC 7766).
       For compatibility, we create a TCP connection for each DNS request. */
    struct tcpdns_worker *workers;
};

struct tcpdns_worker {
    struct proxy_tcpdns *master;
    struct proxy *proxy;

    struct tcpdns_worker *prev;
    struct tcpdns_worker *next;

    /* See RFC 6891 and DNS Flag Day 2020. 4096 should suffice in realworld. */
    char buffer[4096 + 2]; /* +2 for rsz */
    ssize_t nbuffer;

    uint8_t done;
};

/* destroy, and remove from workers list */
static void tcpdns_worker_destroy(struct tcpdns_worker *worker)
{
    struct proxy_tcpdns *master = worker->master;

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
    ssize_t nread, nsent;

    if (event & EPOLLERR) {
        logwarn("tcpdns_worker_handle_event: epoll report an error");
        goto failed;
    }

    if (event & EPOLLIN) {
        nread = proxy_recv(worker->proxy, worker->buffer + worker->nbuffer,
                           sizeof(worker->buffer) - worker->nbuffer);
        if (nread == -EAGAIN) {
            return; /* not finish */
        } else if (nread <= 0) {
            const char *msg = worker->nbuffer == sizeof(worker->buffer)
                ? "over-size DNS packet, drop" : "proxy_recv() failed with EOF";
            logwarn("tcpdns_worker_handle_event: %s", msg);
            goto failed;
        } else {
            worker->nbuffer += nread;
        }

        /* sizeof(rsz) + sizeof(DNS header) */
        if (worker->nbuffer >= 2 + 12) {
            uint16_t rsz;
            const uint64_t one = 1;

            memcpy(&rsz, worker->buffer, sizeof(rsz));
            rsz = ntohs(rsz);

            if (worker->nbuffer < rsz + 2)
                return; /* not finish */

            /* query succeed, destroy worker connection */
            proxy_put(worker->proxy);
            worker->proxy = NULL;

            /* mark we have done and notice master */
            worker->done = 1;
            if (write(worker->master->evfd, &one, sizeof(one)) == -1) {
                logwarn("tcpdns_worker_handle_event: write evfd failed: %s",
                        strerror(errno));
                goto failed;
            }
        }

        return; /* only handle single type of event */
    }

    if (event & EPOLLOUT) {
        nsent = proxy_send(worker->proxy, worker->buffer, worker->nbuffer);
        if (nsent == -EAGAIN) {
            return; /* not finish */
        } else if (nsent <= 0) {
            logwarn("tcpdns_worker_handle_event: proxy_send() failed");
            goto failed;
        } else {
            worker->nbuffer -= nsent;
            memmove(worker->buffer, worker->buffer + nsent, worker->nbuffer);
        }

        if (worker->nbuffer == 0) {
            proxy_evctl(worker->proxy, EPOLLIN, EVUPD);
        }
    }

    return;

failed:
    tcpdns_worker_destroy(worker);
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
static int tcpdns_evctl(struct proxy *proxy, unsigned int event, int mode)
{
    struct proxy_tcpdns *self = container_of(proxy, struct proxy_tcpdns, ops);
    return skutils_evctl(self->loop, self->evfd, &self->events, &self->evfdepcb,
                         event, mode);
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

    if (size + 2 > membersizeof(struct tcpdns_worker, buffer))
        return -E2BIG; /* query too large */

    /* init worker */
    if ((worker = calloc(1, sizeof(struct tcpdns_worker))) == NULL)
        oom();
    worker->master = master;
    sizebe = htobe16(size);
    memcpy(worker->buffer, &sizebe, 2);
    memcpy(worker->buffer + 2, data, size);
    worker->nbuffer = size + 2;

    loglv2("--- tcpdns %zu bytes query", size);

    if (conf->proxytype == PROXY_SOCKS5)
        worker->proxy =
            socks_tcp_create(master->loop, &tcpdns_worker_handle_event, worker,
                             conf->dnssrv, conf->dnsport);
    else if (conf->proxytype == PROXY_HTTP)
        worker->proxy =
            http_tcp_create(master->loop, &tcpdns_worker_handle_event, worker,
                            conf->dnssrv, conf->dnsport);
    else if (conf->proxytype == PROXY_DIRECT)
        worker->proxy =
            direct_tcp_create(master->loop, &tcpdns_worker_handle_event, worker,
                              conf->dnssrv, conf->dnsport);

    if (worker->proxy == NULL) {
        free(worker);
        return -EINVAL;
    }

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
    ssize_t nread;
    size_t szrepl, szcopy;
    uint64_t val;

    if ((nread = read(master->evfd, &val, sizeof(val))) == -1)
        return -errno;

    /* should not happened */
    if (!(nread == sizeof(val) && val == 1))
        return -EIO;

    /* find first worker which marked done */
    for (worker = master->workers; worker; worker = worker->next) {
        if (worker->done)
            break;
    }
    if (!worker)
        return -EAGAIN; /* no worker marked done */

    /* got answer size */
    assert(worker->nbuffer >= 2); /* worker marked done is guaranted this */
    szrepl = worker->nbuffer - 2;

    /* follow UDP socket semantics: silently truncated if buffer is too small */
    szcopy = szrepl <= size ? szrepl : size;
    memcpy(data, worker->buffer + 2, szcopy);

    loglv2("+++ tcpdns %zu bytes answer", szcopy);

    tcpdns_worker_destroy(worker);
    return szcopy;
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
        while (master->workers)
            tcpdns_worker_destroy(master->workers);
        skutils_close_unreg(NULL, master->loop, &master->evfd);
        free(master);
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
                            void *userp)
{
    struct proxy_tcpdns *master;

    loginfo("tcpdns_create: creating new struct proxy_tcpdns");

    if ((master = calloc(1, sizeof(struct proxy_tcpdns))) == NULL)
        oom();

    /* init */
    master->ops.ops = &dns_ops;
    master->loop = loop;
    master->evfdepcb.on_epoll_events = &tcpdns_master_epcb_events;
    master->evfd = -1;
    master->events = 0;
    master->refcnt = 1;
    master->userev = userev;
    master->userp = userp;

    master->evfd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
    if (master->evfd == -1) {
        free(master);
        return NULL;
    }

    skutils_evctl(master->loop, master->evfd, &master->events, &master->evfdepcb,
                  EPOLLOUT | EPOLLIN, EVUPD);

    return &master->ops;
}

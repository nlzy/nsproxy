#include "loop.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"

struct context_loop {
    int tunfd;
    int sigfd;
    int epfd;
    struct netif *tunif;
};

static void tun_input(struct netif *tunif)
{
    struct pbuf *p;
    u16_t len;
    ssize_t readlen;
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    struct context_loop *ctx = tunif->state;

    /* Obtain the size of the packet and put it into the "len"
       variable. */
    readlen = read(ctx->tunfd, buf, sizeof(buf));
    if (readlen < 0) {
        perror("read returned -1");
        exit(1);
    }
    len = (u16_t)readlen;

    /* We allocate a pbuf chain of pbufs from the pool. */
    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p != NULL) {
        pbuf_take(p, buf, len);
        /* acknowledge that packet has been read(); */
    } else {
        LWIP_DEBUGF(NETIF_DEBUG, ("tunif_input: could not allocate pbuf\n"));
    }

    if (p == NULL) {
#if LINK_STATS
        LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
        LWIP_DEBUGF(NETIF_DEBUG,
                    ("tunif_input: low_level_input returned NULL\n"));
        return;
    }

    if (tunif->input(p, tunif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tunif_input: netif input error\n"));
        pbuf_free(p);
    }
}

static err_t tun_output(struct netif *tunif, struct pbuf *p)
{
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    ssize_t written;
    struct context_loop *ctx = tunif->state;

    if (p->tot_len > sizeof(buf)) {
        perror("tapif: packet too large");
        return ERR_IF;
    }

    /* initiate transfer(); */
    pbuf_copy_partial(p, buf, p->tot_len, 0);

    /* signal that packet should be sent(); */
    written = write(ctx->tunfd, buf, p->tot_len);
    if (written < p->tot_len) {
        perror("tapif: write");
        return ERR_IF;
    } else {
        return ERR_OK;
    }
}

err_t tunip4_output(struct netif *netif, struct pbuf *p,
                    const ip4_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

err_t tunip6_output(struct netif *netif, struct pbuf *p,
                    const ip6_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

err_t tunif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'u';

    netif->output = tunip4_output;
    netif->output_ip6 = tunip6_output;
    netif->linkoutput = tun_output;
    netif->mtu = 1500;

    return ERR_OK;
}

void loop_init(struct context_loop **ctx, int tunfd, int sigfd)
{
    struct context_loop *p;
    struct epoll_event ev;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;
    struct netif *tunif;

    if ((p = malloc(sizeof(struct context_loop))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }

    if ((p->epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        perror("epoll_create1()");
        abort();
    }

    p->tunfd = tunfd;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->tunfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, tunfd, &ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    p->sigfd = sigfd;
    ev.events = EPOLLIN;
    ev.data.ptr = &p->sigfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, sigfd, &ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    lwip_init();
    ip4addr_aton(CONFIG_GATEWAY_IP, &tunaddr);
    ip4addr_aton(CONFIG_NETMASK, &tunnetmask);
    ip4addr_aton("0.0.0.0", &tungateway);

    if ((tunif = malloc(sizeof(struct netif))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }
    tunif->state = p;

    netif_add(tunif, &tunaddr, &tunnetmask, &tungateway, &tunfd,
              &tunif_init, &ip_input);
    netif_set_default(tunif);
    netif_set_link_up(tunif);
    netif_set_up(tunif);

    *ctx = p;
}

void loop_deinit(struct context_loop *ctx)
{
    close(ctx->epfd);
    close(ctx->tunfd);
    close(ctx->sigfd);
    free(ctx->tunif);
    free(ctx);
}

int loop_run(struct context_loop *ctx)
{
    int i, nevent;
    struct ep_poller *poller;
    struct epoll_event ev[1]; /* TODO: batch event */

    for (;;) {
        if ((nevent = epoll_wait(ctx->epfd, ev, sizeof(ev) / sizeof(*ev),
                                 -1)) == -1) {
            if (errno != EINTR) {
                perror("epoll_wait()");
                abort();
            }
        }

        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &ctx->tunfd) {
                tun_input(ctx->tunif);
            } else if (ev[i].data.ptr == &ctx->sigfd) {
                loop_deinit(ctx);
                fprintf(stderr, "Bye ~\n");
                return 0;
            } else {
                poller = ev[i].data.ptr;
                poller->on_epoll_event(poller, ev[i].events);
            }
        }
    }
}

int loop_epfd(struct context_loop *ctx)
{
    return ctx->epfd;
}

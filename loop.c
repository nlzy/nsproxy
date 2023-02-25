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
    struct context_loop *ctx = tunif->state;
    char buffer[CONFIG_MTU];
    ssize_t nread;
    struct pbuf *p;

    if ((nread = read(ctx->tunfd, buffer, sizeof(buffer))) == -1) {
        perror("read()");
        abort();
    }

    if ((p = pbuf_alloc(PBUF_RAW, nread, PBUF_RAM)) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    pbuf_take(p, buffer, nread);

    if (tunif->input(p, tunif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_input: netif input error\n"));
        pbuf_free(p);
    }
}

static err_t tun_output(struct netif *tunif, struct pbuf *p)
{
    struct context_loop *ctx = tunif->state;
    char buffer[CONFIG_MTU];
    ssize_t nwrite;

    if (p->tot_len > sizeof(buffer)) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: packet too large\n"));
        return ERR_IF;
    }

    pbuf_copy_partial(p, buffer, p->tot_len, 0);

    if ((nwrite = write(ctx->tunfd, buffer, p->tot_len)) == -1) {
        perror("write()");
        abort();
    }
    if (nwrite != p->tot_len) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: partial write\n"));
        return ERR_IF;
    }

    return ERR_OK;
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
    netif->mtu = CONFIG_MTU;

    return ERR_OK;
}

void loop_init(struct context_loop **ctx, int tunfd, int sigfd)
{
    struct context_loop *p;
    struct epoll_event ev;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;

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

    if ((p->tunif = malloc(sizeof(struct netif))) == NULL) {
        fprintf(stderr, "Out of Memory\n");
        abort();
    }
    netif_add(p->tunif, &tunaddr, &tunnetmask, &tungateway, p, &tunif_init,
              &ip_input);
    netif_set_default(p->tunif);
    netif_set_link_up(p->tunif);
    netif_set_up(p->tunif);

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
                                 250)) == -1) {
            if (errno != EINTR) {
                perror("epoll_wait()");
                abort();
            }
        }

        if (nevent == 0) {
            sys_check_timeouts();
            continue;
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
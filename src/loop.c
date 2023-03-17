#include "loop.h"

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

struct loopctx {
    int tunfd;
    int sigfd;
    int epfd;
    int timerfd;
    struct netif tunif;
    struct loopconf conf;
};

static void tun_input(struct netif *tunif)
{
    struct loopctx *loop = tunif->state;
    ssize_t nread;
    struct pbuf *p;

    if ((p = pbuf_alloc(PBUF_RAW, NSPROXY_MTU, PBUF_RAM)) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
        abort();
    }

    if ((nread = read(loop->tunfd, p->payload, p->len)) == -1) {
        perror("read()");
        abort();
    }

    /* shirk, set p->tot_len = nread */
    pbuf_realloc(p, nread);

    if (tunif->input(p, tunif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_input: netif input error\n"));
        pbuf_free(p);
    }
}

static err_t tun_output(struct netif *tunif, struct pbuf *p)
{
    struct loopctx *loop = tunif->state;
    struct pbuf *orig = p;
    struct iovec iov[16];
    size_t n = 0;
    ssize_t nwrite;

    if (p->tot_len > NSPROXY_MTU) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: packet too large\n"));
        return ERR_IF;
    }

    while (n != arraysizeof(iov)) {
        iov[n].iov_base = p->payload;
        iov[n].iov_len = p->len;
        n++;
        /* lwip used below as loop end condiction, not p->next == NULL */
        if (p->len == p->tot_len)
            break;
        else
            p = p->next;
    }
    if ((nwrite = writev(loop->tunfd, iov, n)) == -1) {
        perror("write()");
        abort();
    }
    if (nwrite != orig->tot_len) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: partial write\n"));
        return ERR_IF;
    }

    return ERR_OK;
}

static err_t tunip4_output(struct netif *netif, struct pbuf *p,
                           const ip4_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

static err_t tunip6_output(struct netif *netif, struct pbuf *p,
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
    netif->mtu = NSPROXY_MTU;

    return ERR_OK;
}

void loop_init(struct loopctx **loop, struct loopconf *conf, int tunfd,
               int sigfd)
{
    struct loopctx *p;
    struct epoll_event ev;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;
    struct itimerspec its = { .it_interval.tv_nsec = 250000000,
                              .it_value.tv_nsec = 250000000 };

    if ((p = malloc(sizeof(struct loopctx))) == NULL) {
        fprintf(stderr, "Out of Memory.\n");
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

    /* lwip required call to some functions periodically every 250ms */
    if ((p->timerfd = timerfd_create(CLOCK_MONOTONIC,
                                     TFD_NONBLOCK | TFD_CLOEXEC)) == -1) {
        perror("timerfd_create()");
        abort();
    }
    if ((timerfd_settime(p->timerfd, 0, &its, NULL)) == -1) {
        perror("timerfd_settime()");
        abort();
    }
    ev.events = EPOLLIN;
    ev.data.ptr = &p->timerfd;
    if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, p->timerfd, &ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    lwip_init();
    ip4addr_aton(NSPROXY_GATEWAY_IP, &tunaddr);
    ip4addr_aton(NSPROXY_NETMASK, &tunnetmask);
    ip4addr_aton("0.0.0.0", &tungateway);

    netif_add(&p->tunif, &tunaddr, &tunnetmask, &tungateway, p, &tunif_init,
              &ip_input);
    netif_set_default(&p->tunif);
    netif_set_link_up(&p->tunif);
    netif_set_up(&p->tunif);

    memcpy(&p->conf, conf, sizeof(p->conf));

    *loop = p;
}

void loop_deinit(struct loopctx *loop)
{
    close(loop->epfd);
    close(loop->tunfd);
    close(loop->sigfd);
    close(loop->timerfd);
    netif_remove(&loop->tunif);
    free(loop);
}

int loop_run(struct loopctx *loop)
{
    int i, nevent;
    size_t epoch = 0;
    uint64_t expired;
    struct ep_poller *poller;
    struct signalfd_siginfo sig;
    struct epoll_event ev[1]; /* TODO: batch event */

    for (;;) {
        if ((nevent = epoll_wait(loop->epfd, ev, arraysizeof(ev), -1)) == -1) {
            if (errno != EINTR) {
                perror("epoll_wait()");
                abort();
            }
        }

        for (i = 0; i < nevent; i++) {
            if (ev[i].data.ptr == &loop->tunfd) {
                tun_input(&loop->tunif);
            } else if (ev[i].data.ptr == &loop->sigfd) {
                if (read(loop->sigfd, &sig, sizeof(sig)) == -1) {
                    perror("read()");
                    abort();
                }
                if (sig.ssi_signo == SIGCHLD) {
                    loglv(1, "nsproxy is closing, bye~");
                    loop_deinit(loop);
                    return 0;
                }
            } else if (ev[i].data.ptr == &loop->timerfd) {
                if (read(loop->timerfd, &expired, sizeof(expired)) == -1) {
                    perror("read()");
                    abort();
                }
                while (expired--) {
                    if (epoch % 4 == 0) {
                        udp_tmr();
                        ip_reass_tmr();
                        ip6_reass_tmr();
                        nd6_tmr();
                    }
                    tcp_tmr();
                    epoch++;
                }
            } else {
                poller = ev[i].data.ptr;
                poller->on_epoll_event(poller, ev[i].events);
            }
        }
    }
}

int loop_epfd(struct loopctx *loop)
{
    return loop->epfd;
}

struct loopconf *loop_conf(struct loopctx *loop)
{
    return &loop->conf;
}

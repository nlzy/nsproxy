#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip.h"

#define CONFIG_LOCAL_IP   "172.23.255.255"
#define CONFIG_GATEWAY_IP "172.23.255.254"
#define CONFIG_NETMASK    "255.255.255.254"

static void write_string(const char *fname, const char *str)
{
    int fd;

    if ((fd = open(fname, O_WRONLY | O_APPEND | O_CLOEXEC)) == -1) {
        perror("open()");
        abort();
    }

    if (write(fd, str, strlen(str)) == -1) {
        perror("write()");
        abort();
    }

    close(fd);
}

void map_uid(unsigned from, unsigned to)
{
    char str[32];
    snprintf(str, sizeof(str), "%d %d 1\n", from, to);
    write_string("/proc/self/uid_map", str);
}

void map_gid(unsigned from, unsigned to)
{
    char str[32];
    snprintf(str, sizeof(str), "%d %d 1\n", from, to);
    write_string("/proc/self/gid_map", str);
}

void set_setgroups(const char *action)
{
    write_string("/proc/self/setgroups", action);
}

void bringup_loopback()
{
    int sk;
    struct ifreq ifr = { .ifr_name = "lo", .ifr_flags = IFF_UP | IFF_RUNNING };

    if ((sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        abort();
    }

    if (ioctl(sk, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl()");
        abort();
    }

    close(sk);
}

int bringup_tun()
{
    int tunfd, sk;
    struct ifreq ifr = { .ifr_name = "tun0" };
    struct sockaddr_in *sai;
    struct rtentry route = { 0 };

    if ((sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        abort();
    }

    if ((tunfd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) == -1) {
        perror("open()");
        abort();
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(tunfd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl()");
        abort();
    }

    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sk, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl()");
        abort();
    }

    ifr.ifr_mtu = 1500;
    if (ioctl(sk, SIOCSIFMTU, &ifr) == -1) {
        perror("ioctl()");
        abort();
    }

    sai = (struct sockaddr_in *)&ifr.ifr_addr;
    sai->sin_family = AF_INET;

    inet_pton(AF_INET, CONFIG_LOCAL_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl()");
        abort();
    }

    inet_pton(AF_INET, CONFIG_GATEWAY_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCGIFDSTADDR, &ifr) < 0) {
        perror("ioctl()");
        abort();
    }

    inet_pton(AF_INET, CONFIG_NETMASK, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFNETMASK, &ifr) < 0) {
        perror("cannot set device netmask");
        abort();
    }

    sai = (struct sockaddr_in *)&route.rt_gateway;
    sai->sin_family = AF_INET;
    inet_pton(AF_INET, CONFIG_GATEWAY_IP, &sai->sin_addr);

    sai = (struct sockaddr_in *)&route.rt_dst;
    sai->sin_family = AF_INET;
    sai->sin_addr.s_addr = INADDR_ANY;

    sai = (struct sockaddr_in *)&route.rt_genmask;
    sai->sin_family = AF_INET;
    sai->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;
    route.rt_dev = ifr.ifr_name;

    if (ioctl(sk, SIOCADDRT, &route) < 0) {
        perror("set route");
        abort();
    }

    close(sk);
    return tunfd;
}

void send_fd(int sock, int fd)
{
    char dummy = '\0';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = { .msg_name = NULL,
                          .msg_namelen = 0,
                          .msg_iov = &iov,
                          .msg_iovlen = 1,
                          .msg_control = cmsgbuf,
                          .msg_controllen = sizeof(cmsgbuf) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(&CMSG_DATA(cmsg), &fd, sizeof(fd));

    if (sendmsg(sock, &msg, 0) == -1) {
        perror("sendmsg()");
        abort();
    }
}

int recv_fd(int sock)
{
    int ret;
    ssize_t nrecv;
    char dummy = '\0';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = { .msg_name = NULL,
                          .msg_namelen = 0,
                          .msg_iov = &iov,
                          .msg_iovlen = 1,
                          .msg_control = cmsgbuf,
                          .msg_controllen = sizeof(cmsgbuf) };
    struct cmsghdr *cmsg;

    if ((nrecv = recvmsg(sock, &msg, 0)) < 0) {
        perror("recvmsg()");
        abort();
    }
    if (nrecv == 0) {
        fprintf(stderr, "the message is empty.\n");
        abort();
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "the message does not contain fd.\n");
        abort();
    }

    memcpy(&ret, CMSG_DATA(cmsg), sizeof(ret));
    return ret;
}





/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/
static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    int *tunfd = netif->state;
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    ssize_t written;

    if (p->tot_len > sizeof(buf)) {
        perror("tapif: packet too large");
        return ERR_IF;
    }

    /* initiate transfer(); */
    pbuf_copy_partial(p, buf, p->tot_len, 0);

    /* signal that packet should be sent(); */
    written = write(*tunfd, buf, p->tot_len);
    if (written < p->tot_len) {
        perror("tapif: write");
        return ERR_IF;
    } else {
        return ERR_OK;
    }
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *low_level_input(struct netif *netif)
{
    struct pbuf *p;
    u16_t len;
    ssize_t readlen;
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    int *tunfd = netif->state;

    /* Obtain the size of the packet and put it into the "len"
       variable. */
    readlen = read(*tunfd, buf, sizeof(buf));
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

    return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * tunif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void tunif_input(struct netif *netif)
{
    struct pbuf *p = low_level_input(netif);

    if (p == NULL) {
#if LINK_STATS
        LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
        LWIP_DEBUGF(NETIF_DEBUG,
                    ("tunif_input: low_level_input returned NULL\n"));
        return;
    }

    if (netif->input(p, netif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tunif_input: netif input error\n"));
        pbuf_free(p);
    }
}

err_t ethip4_output(struct netif *netif, struct pbuf *p,
                    const ip4_addr_t *ipaddr)
{
    return low_level_output(netif, p);
}

err_t ethip6_output(struct netif *netif, struct pbuf *p,
                    const ip6_addr_t *ipaddr)
{
    return low_level_output(netif, p);
}

err_t tunif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'u';

    netif->output = ethip4_output;
    netif->output_ip6 = ethip6_output;
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;

    /* Obtain MAC address from network interface. */

    /* (We just fake an address...) */
    netif->hwaddr[0] = 0x02;
    netif->hwaddr[1] = 0x12;
    netif->hwaddr[2] = 0x34;
    netif->hwaddr[3] = 0x56;
    netif->hwaddr[4] = 0x78;
    netif->hwaddr[5] = 0xab;
    netif->hwaddr_len = 6;

    /* device capabilities */
    netif->flags = 0;

    netif_set_link_up(netif);

    return ERR_OK;
}



int parent(int sk)
{
    int tunfd;
    int childfd;
    sigset_t mask;
    char dummy = '\0';
    int i, nevent;
    struct epoll_event ev;
    int epfd;
    struct netif tunif = { 0 };
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;

    tunfd = recv_fd(sk);
    fprintf(stderr, "recv_fd: %d\n", tunfd);

    if (sigemptyset(&mask) == -1) {
        perror("sigemptyset()");
        abort();
    }
    if (sigaddset(&mask, SIGCHLD) == -1) {
        perror("sigaddset()");
        abort();
    }
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        perror("sigprocmask()");
        abort();
    }

    if ((childfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK)) == -1) {
        perror("signalfd()");
        abort();
    }

    /* write a byte after setting up sigmask, indicate set up completely */
    if (write(sk, &dummy, sizeof(dummy)) == -1) {
        perror("write()");
        abort();
    }

    close(sk);

    if ((epfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        perror("epoll_create1()");
        abort();
    }

    ev.events = EPOLLIN;
    ev.data.ptr = &tunfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tunfd, &ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    ev.events = EPOLLIN;
    ev.data.ptr = &childfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, childfd, &ev) == -1) {
        perror("epoll_ctl()");
        abort();
    }

    lwip_init();

    ip4addr_aton(CONFIG_GATEWAY_IP, &tunaddr);
    ip4addr_aton(CONFIG_NETMASK, &tunnetmask);
    ip4addr_aton("0.0.0.0", &tungateway);

    netif_add(&tunif, &tunaddr, &tunnetmask, &tungateway, &tunfd, &tunif_init, &ip_input);
    netif_set_default(&tunif);
    netif_set_link_up(&tunif);
    netif_set_up(&tunif);


    /* MAIN LOOP */

    for (;;) {
        if ((nevent = epoll_wait(epfd, &ev, 1, -1)) == -1) {
            if (errno != EINTR) {
                perror("epoll_wait()");
                abort();
            }
        }

        if (ev.data.ptr == &tunfd) {
            tunif_input(&tunif);
        } else if (ev.data.ptr == &childfd) {
            fprintf(stderr, "Bye ~\n");
            return 0;
        }
    }
}

int child(int sk, char *cmd[])
{
    int tunfd;
    char dummy;

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
        perror("unshare()");
        abort();
    }

    map_uid(0, 1000);

    set_setgroups("deny");

    map_gid(0, 1000);

    write_string("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");

    bringup_loopback();

    tunfd = bringup_tun();

    send_fd(sk, tunfd);

    /* wait for parent to set his sigmask,
       prevent child process terminate befor parent sets sigmask  */
    if (read(sk, &dummy, sizeof(dummy)) == -1) {
        perror("read()");
        abort();
    }

    close(sk);

    if (execv(cmd[0], cmd + 1) == -1) {
        perror("execv()");
        abort();
    }

    /* never reach */
    return 0;
}

int main(int argc, char *argv[])
{
    int skpair[2];
    pid_t cid;
    char **cmd;
    char *defcmd[2];

    if (socketpair(AF_UNIX, SOCK_STREAM | SFD_CLOEXEC, 0, skpair) == -1) {
        perror("socketpair()");
        abort();
    }

    if ((cid = fork()) == -1) {
        perror("fork()");
        abort();
    }

    if (cid) {
        close(skpair[1]);

        return parent(skpair[0]);
    } else {
        close(skpair[0]);

        if (argc < 2) {
            defcmd[0] = strdup("/bin/bash");
            defcmd[1] = NULL;
            cmd = defcmd;
        } else {
            cmd = argv + 1;
        }

        return child(skpair[1], cmd);
    }
}

void sys_init(void)
{
}

int sys_now(void)
{
    return 0;
}

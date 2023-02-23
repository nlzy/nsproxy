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
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "loop.h"

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

int parent(int sk)
{
    int tunfd;
    int childfd;
    sigset_t mask;
    struct context_loop *ctx;
    char dummy = '\0';

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

    loop_init(&ctx, tunfd, childfd);
    return loop_run(ctx);
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

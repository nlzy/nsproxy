#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "loop.h"
#include "lwip/opt.h"

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

static void map_uid(unsigned int from, unsigned int to)
{
    char str[32];
    snprintf(str, sizeof(str), "%u %u 1\n", from, to);
    write_string("/proc/self/uid_map", str);
}

static void map_gid(unsigned int from, unsigned int to)
{
    char str[32];
    snprintf(str, sizeof(str), "%u %u 1\n", from, to);
    write_string("/proc/self/gid_map", str);
}

static void set_setgroups(const char *action)
{
    write_string("/proc/self/setgroups", action);
}

static void bringup_loopback(void)
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

static int bringup_tun(void)
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

    ifr.ifr_mtu = NSPROXY_MTU;
    if (ioctl(sk, SIOCSIFMTU, &ifr) == -1) {
        perror("ioctl()");
        abort();
    }

    sai = (struct sockaddr_in *)&ifr.ifr_addr;
    sai->sin_family = AF_INET;

    inet_pton(AF_INET, NSPROXY_LOCAL_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl()");
        abort();
    }

    inet_pton(AF_INET, NSPROXY_GATEWAY_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCGIFDSTADDR, &ifr) < 0) {
        perror("ioctl()");
        abort();
    }

    inet_pton(AF_INET, NSPROXY_NETMASK, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFNETMASK, &ifr) < 0) {
        perror("cannot set device netmask");
        abort();
    }

    sai = (struct sockaddr_in *)&route.rt_gateway;
    sai->sin_family = AF_INET;
    inet_pton(AF_INET, NSPROXY_GATEWAY_IP, &sai->sin_addr);

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

static void send_fd(int sock, int fd)
{
    char dummy = '\0';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = { 0 };
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

static int recv_fd(int sock)
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

    if ((nrecv = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC)) < 0) {
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

static int parent(int sk, struct loopconf *conf)
{
    int tunfd;
    int childfd;
    sigset_t mask;
    struct loopctx *loop;
    char dummy = '\0';

    tunfd = recv_fd(sk);

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

    loop_init(&loop, conf, tunfd, childfd);
    return loop_run(loop);
}

static int child(int sk, char *cmd[])
{
    int tunfd;
    char dummy;
    uid_t uid, gid;

    if (unshare(CLONE_NEWNET) == -1) {
        /* Failed, of cause. Unprivileged users can't create net_namespace.
           Try to create with a user_namespace */
        uid = getuid();
        gid = getgid();

        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
            perror("unshare()");
            abort();
        }

        set_setgroups("deny");

        map_uid(uid, uid);
        map_gid(gid, gid);
    }

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

    if (execvp(cmd[0], cmd) == -1) {
        perror("execvp()");
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
    int opt, err;
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    struct loopconf conf;
    const char *serv = NULL;
    const char *port = NULL;
    const char *dns = NULL;
    int ishttp = 0;

    while ((opt = getopt(argc, argv, "+Hs:p:d:")) != -1) {
        switch (opt) {
        case 'H':
            ishttp = 1;
            break;
        case 's':
            serv = optarg;
            break;
        case 'p':
            port = optarg;
            break;
        case 'd':
            dns = optarg;
            break;
        default:
            break;
        }
    }

    if (serv == NULL)
        serv = "127.0.0.1";

    if (port == NULL)
        port = ishttp ? "8080" : "1080";

    if (dns == NULL)
        dns = "tcp://8.8.8.8";

    /* resolve domain to ip address */
    if ((err = getaddrinfo(serv, port, &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(err));
        abort();
    }
    if (result->ai_family == AF_INET) {
        inet_ntop(result->ai_family,
                  &((struct sockaddr_in *)result->ai_addr)->sin_addr,
                  conf.proxysrv, sizeof(conf.proxysrv));
    } else if (result->ai_family == AF_INET6) {
        inet_ntop(result->ai_family,
                  &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr,
                  conf.proxysrv, sizeof(conf.proxysrv));
    } else {
        fprintf(stderr, "Unsupported proxy server address type.\n");
        abort();
    }
    strncpy(conf.proxyport, port, sizeof(conf.proxyport));
    conf.proxytype = ishttp ? PROXY_HTTP : PROXY_SOCKS5;

    freeaddrinfo(result);

    if (strcmp(dns, "off") == 0) {
        conf.dnstype = DNSHIJACK_OFF;
    } else if (strcmp(dns, "direct") == 0) {
        conf.dnstype = DNSHIJACK_DIRECT;
    } else if (strstr(dns, "tcp://") == dns) {
        conf.dnstype = DNSHIJACK_TCP;
        strncpy(conf.dnssrv, dns + strlen("tcp://"), sizeof(conf.dnssrv) - 1);
    } else if (strstr(dns, "udp://") == dns) {
        conf.dnstype = DNSHIJACK_UDP;
        strncpy(conf.dnssrv, dns + strlen("udp://"), sizeof(conf.dnssrv) - 1);
    } else {
        fprintf(stderr, "Unsupported dns address type.\n");
        abort();
    }

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
        return parent(skpair[0], &conf);
    } else {
        close(skpair[0]);
        if (optind >= argc) {
            defcmd[0] = strdup("/bin/bash");
            defcmd[1] = NULL;
            cmd = defcmd;
        } else {
            cmd = argv + optind;
        }
        return child(skpair[1], cmd);
    }
}

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
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "common.h"
#include "core.h"
#include "loop.h"
#include "csignal.h"
#include "lwipopts.h"

int nsproxy_verbose_level__ = 0;
struct nspconf *nsproxy_current_nspconf__ = NULL;

const char nsproxy_help_message__[] =
    "Usage: nsproxy [OPTIONS...] <COMMAND> [ARGS...]\n"
    "\n"
    "Run COMMAND in a namespace and redirect its connections to a proxy.\n"
    "\n"
    "Common Options:\n"
    "  -H               Use an HTTP proxy instead of SOCKS5\n"
    "  -s <server>      Set the proxy server address\n"
    "  -p <port>        Set the proxy server port\n"
    "  -d <dns>         Redirect DNS queries to <tcp|udp>://<IP>[:PORT] or \"off\"\n"
    "  -a <user:pass>   Set the proxy username and password\n"
    "  -6               Enable IPv6 support\n"
    "  -v               Increase verbosity\n"
    "  -q               Be quiet\n"
    "\n"
    "For more details, see nsproxy(1).\n";

const char nsproxy_version_message__[] =
    "nsproxy v" STRINGIFY(NSPROXY_VERSION) "\n\n"
    "Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>\n"
    "This is free software: you are free to change and redistribute it under GPLv2+.\n"
    "There is ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.\n";

static ssize_t write_all(int fd, const void *data, size_t size)
{
    const char *p = data;
    ssize_t w, written = 0;

    if (size > SSIZE_MAX)
        return -EINVAL;

    do { /* use do-while to ensure that write() is called at least once */
        if ((w = write(fd, p + written, (ssize_t)size - written)) == -1)
            return -errno;
        if (w == 0)
            return (size > 0) ? -EIO : 0;
        written += w;
    } while (written < (ssize_t)size);

    return written;
}

static ssize_t write_string(const char *fname, const char *str)
{
    int fd;
    ssize_t w;

    if ((fd = open(fname, O_WRONLY | O_TRUNC | O_CLOEXEC)) == -1) {
        return -errno;
    }

    w = write_all(fd, str, strlen(str));

    close(fd);
    return w;
}

/* path is an accessible directory containing at least one non-dot-entry */
static int has_nondotentry(const char *path)
{
    DIR *dir;
    struct dirent *ent;
    int found = 0;

    if ((dir = opendir(path)) == NULL)
        return 0; /* failed, path may not accessible, or isn't a directory */

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] != '.') {
            found = 1; /* found a non-dot-entry */
            break;
        }
    }

    closedir(dir);
    return found;
}

static void map_ids(uid_t uid, uid_t gid)
{
    unsigned long luid = uid, lgid = gid;
    ssize_t nwrite;
    char buff[64];

    snprintf(buff, sizeof(buff), "%lu %lu 1\n", luid, luid);
    if ((nwrite = write_string("/proc/self/uid_map", buff)) < 0) {
        fprintf(stderr, "Error: write uid_map failed: %s\n", strerror(-nwrite));
        exit(EXIT_FAILURE);
    }

    snprintf(buff, sizeof(buff), "%lu %lu 1\n", lgid, lgid);
    if ((nwrite = write_string("/proc/self/gid_map", buff)) < 0) {
        fprintf(stderr, "Error: write gid_map failed: %s\n", strerror(-nwrite));
        exit(EXIT_FAILURE);
    }
}

static void bringup_loopback(void)
{
    int sk;
    struct ifreq ifr = { .ifr_name = "lo", .ifr_flags = IFF_UP | IFF_RUNNING };

    if ((sk = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (!current_nspconf()->ipv6) {
        write_string("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "1");
    }

    if (ioctl(sk, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl(SIOCSIFFLAGS)");
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    /* create tun0 */
    if ((tunfd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC)) == -1) {
        if (errno == ENOENT) {
            fprintf(stderr,
                    "nsproxy: open \"/dev/net/tun\" failed.\n"
                    "hints: If you are using OpenWrt, install the package "
                    "'kmod-tun'.\n"
                    "       If you are inside LXC or Docker container, add "
                    "device '/dev/net/tun' to the container.\n");
            exit(EXIT_FAILURE);
        } else {
            perror("open(/dev/net/tun)");
            exit(EXIT_FAILURE);
        }
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(tunfd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl(TUNSETIFF)");
        exit(EXIT_FAILURE);
    }

    /* configure tun0 */
    ifr.ifr_mtu = NSPROXY_MTU;
    if (ioctl(sk, SIOCSIFMTU, &ifr) == -1) {
        perror("ioctl(SIOCSIFMTU)");
        exit(EXIT_FAILURE);
    }
    if (current_nspconf()->ipv6) {
        /* return value is not checked, failure is allowed. */
        write_string("/proc/sys/net/ipv6/conf/tun0/"
                     "mldv1_unsolicited_report_interval", "0");
        write_string("/proc/sys/net/ipv6/conf/tun0/"
                     "mldv2_unsolicited_report_interval", "0");
        write_string("/proc/sys/net/ipv6/conf/tun0/router_solicitations", "0");
    } else {
        write_string("/proc/sys/net/ipv6/conf/tun0/disable_ipv6", "1");
    }

    /* up tun0 */
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sk, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl(SIOCSIFFLAGS)");
        exit(EXIT_FAILURE);
    }

    /* configure IPv4 addr */
    sai = (struct sockaddr_in *)&ifr.ifr_addr;
    sai->sin_family = AF_INET;
    inet_pton(AF_INET, NSPROXY_LOCAL_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        exit(EXIT_FAILURE);
    }
    inet_pton(AF_INET, NSPROXY_NETMASK, &sai->sin_addr);
    if (ioctl(sk, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        exit(EXIT_FAILURE);
    }

    /* configure IPv4 route */
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
        perror("ioctl(SIOCADDRT)");
        exit(EXIT_FAILURE);
    }

    loginfo("child: brought up tun device and configured IPv4");

    close(sk);
    return tunfd;
}

static void setup_ipv6(void)
{
    int sk;
    struct ifreq ifr = { .ifr_name = "tun0" };
    struct in6_ifreq ifr6 = { 0 };
    struct in6_rtmsg rtmsg6 = { 0 };

    if ((sk = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }

    /* add ipv6 address */
    inet_pton(AF_INET6, NSPROXY_LOCAL_IPV6, &ifr6.ifr6_addr);
    ifr6.ifr6_prefixlen = NSPROXY_PREFIXLEN;
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;

    if (ioctl(sk, SIOCSIFADDR, &ifr6) < 0) {
        perror("ioctl(SIOCSIFADDR) IPv6");
        exit(EXIT_FAILURE);
    }

    /* add ipv6 default gateway */
    inet_pton(AF_INET6, NSPROXY_GATEWAY_IPV6, &rtmsg6.rtmsg_gateway);
    rtmsg6.rtmsg_dst_len = 0; /* ::/0 */
    rtmsg6.rtmsg_src_len = 0;
    rtmsg6.rtmsg_metric = 1;
    rtmsg6.rtmsg_flags = RTF_UP | RTF_GATEWAY;
    rtmsg6.rtmsg_ifindex = ifr.ifr_ifindex;

    if (ioctl(sk, SIOCADDRT, &rtmsg6) < 0) {
        perror("ioctl(SIOCADDRT) IPv6");
        exit(EXIT_FAILURE);
    }

    loginfo("child: configured IPv6");
    close(sk);
}

static int overwrite_conf(const char *target, const char *content, uint8_t ro)
{
    int fd;
    char tmpname[] = "/tmp/nsproxy-overwrite-XXXXXX";

    if ((fd = mkstemp(tmpname)) == -1)
        goto failed_on_create;

    if (chmod(tmpname, 0644) == -1)
        goto failed_after_create;

    if (write_all(fd, content, strlen(content)) < 0)
        goto failed_after_create;

    if (mount(tmpname, target, NULL, MS_BIND, NULL) == -1)
        goto failed_after_create;

    if (ro) {
        /* try to remount, failure is allow */
        mount(tmpname, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
    }

    loginfo("child: re-bound %s", target);

    close(fd);
    unlink(tmpname);
    return 0;

failed_after_create:
    close(fd);
    unlink(tmpname);
failed_on_create:
    return -1;
}

/* create mount namespace, and make it isolate really */
static int unshare_mount(void)
{
    struct nspconf *conf = current_nspconf();

    if (unshare(CLONE_NEWNS) == -1)
        goto failed_unshare;
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1)
        goto failed_unshare;

    loginfo("child: created mount namespace");

    /* OpenSSH client (ssh) exited with following message:
       > 'Bad owner or permissions on /etc/ssh/ssh_config.d/foobar.conf'
       That's caused by user_namespace mapped uid 0 to overflow uid, ssh
       misunderstood as owner of the config file is bad.
       XXX: mount a tmpfs and leave ssh_config.d empty to make ssh happy. */
    if (has_nondotentry("/etc/ssh/ssh_config.d")) {
        if (mount("tmpfs", "/etc/ssh/ssh_config.d", "tmpfs", 0, NULL) == -1)
            loglv0("Warning: re-mounted /etc/ssh/ssh_config.d failed. "
                   "OpenSSH client (ssh) may not work.");
        else
            loginfo("child: mounted /etc/ssh/ssh_config.d");
    }

    /* ensure DNS redirection work */
    if (conf->dnstype != DNS_REDIR_OFF) {
        if (overwrite_conf("/etc/resolv.conf",
                           "nameserver " NSPROXY_GATEWAY_IP "\n", 1) < 0)
            loglv0("Warning: re-bind /etc/resolv.conf failed. DNS redirect may "
                   "not work.");
        if (overwrite_conf("/etc/nsswitch.conf", "hosts: files dns\n", 1) < 0)
            loglv0("Warning: re-bind /etc/nsswitch.conf failed. DNS redirect may "
                   "not work.");
    }

    return 0;

failed_unshare:
    loglv0("Warning: create mount namespace failed. DNS redirect may not work.");
    return -1;
}

/* return 0 on unprivileged approach, 1 on privileged */
static int unshare_net(void)
{
    ssize_t nwrite;
    uid_t uid;
    gid_t gid;

    /* privileged approach, which avoids creating a extra userns */
    if (unshare(CLONE_NEWNET) == 0) {
        loginfo("child: created net namespace (privileged)");
        return 1;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        fprintf(stderr, "nsproxy: create net_namespace failed.\n"
                        "nsproxy: This kernel may not have net_namespace "
                        "support enabled.\n");
        exit(EXIT_FAILURE);
    }

    /* save original ids before create userns */
    uid = getuid();
    gid = getgid();

    /* unprivileged approach */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == -1) {
        fprintf(stderr,
                "nsproxy: create net_namespace failed: %s\n"
                "hint: If you are using Debian <= 10, add the following "
                "content to /etc/sysctl.d/70-unprivileged-userns.conf\n"
                "    kernel.unprivileged_userns_clone=1\n"
                "then run command (with root)\n"
                "    sysctl -p /etc/sysctl.d/70-unprivileged-userns.conf\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* deny setgroups is regular practice, also check userns succeeded on ubuntu */
    if ((nwrite = write_string("/proc/self/setgroups", "deny")) < 0) {
        fprintf(stderr,
                "nsproxy: set groups failed: %s\n"
                "hints: If you are using Ubuntu >= 23.10, add the following "
                "content to /etc/sysctl.d/70-apparmor-userns.conf\n"
                "    kernel.apparmor_restrict_unprivileged_userns=0\n"
                "then run command (with root)\n"
                "    sysctl -p /etc/sysctl.d/70-apparmor-userns.conf\n",
                strerror(-nwrite));
        exit(EXIT_FAILURE);
    }

    map_ids(uid, gid);

    loginfo("child: created user and net namespace (unprivileged)");
    return 0;
}

/* raise RLIMIT_NOFILE soft limit to 'num' but not exceed hard limit
   return 0 if succeed, -errno if failed */
static int raise_nofile(unsigned int num)
{
    struct rlimit rl;
    rlim_t old;

    if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
        return -errno;
    if (rl.rlim_cur > num) /* no need to raise */
        return 0;
    old = rl.rlim_cur;

    /* set soft limit to num but not exceed hard limit */
    rl.rlim_cur = (num <= rl.rlim_max) ? num : rl.rlim_max; 
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
        return -errno;

    loginfo("parent: raised nofile soft limit from %lu to %lu",
            (unsigned long)old, (unsigned long)rl.rlim_cur);
    return 0;
}

/* send a file descriptor to sock
   must succeed, otherwise terminate this process */
static void send_fd(int sock, int fd)
{
    char dummy = '\0';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr msg = { .msg_iov = &iov,
                          .msg_iovlen = 1,
                          .msg_control = cmsgbuf,
                          .msg_controllen = sizeof(cmsgbuf) };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    if (sendmsg(sock, &msg, MSG_NOSIGNAL) == -1) {
        perror("sendmsg()");
        exit(EXIT_FAILURE);
    }
}

/* receive a file descriptor from sock, return the file descriptor
   must succeed, otherwise terminate this process */
static int recv_fd(int sock)
{
    int ret;
    ssize_t nrecv;
    char dummy = '\0';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    char cmsgbuf[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr msg = { .msg_iov = &iov,
                          .msg_iovlen = 1,
                          .msg_control = cmsgbuf,
                          .msg_controllen = sizeof(cmsgbuf) };
    struct cmsghdr *cmsg;

    if ((nrecv = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC)) < 0) {
        perror("recvmsg()");
        exit(EXIT_FAILURE);
    }
    if (nrecv == 0) {
        exit(EXIT_FAILURE);
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS
        || cmsg->cmsg_len != CMSG_LEN(sizeof(ret))) {
        fprintf(stderr, "nsproxy: bad cmsg in recv_fd()\n");
        exit(EXIT_FAILURE);
    }

    memcpy(&ret, CMSG_DATA(cmsg), sizeof(ret));
    return ret;
}

/* tasks in parent process are:
   1. Receive TUN file descriptor from child process.
   2. Initialize lwIP / event loop / child signalfd.
   3. Notify the child that parent is ready.
   4. Start the event loop, keep the event loop running, the event loop will
      handle IP packets from TUN device and forward traffic to proxy server.
*/
static int parent(int sk, pid_t cid)
{
    int tunfd;
    struct csigctx csig = { 0 };
    struct loopctx *loop;
    struct corectx *core;

    /* a little more than C10K, failure is not check */
    raise_nofile(10240);

    tunfd = recv_fd(sk);

    csig.cid = cid;
    if ((csig.sigfd = csignal_initfd()) < 0) {
        fprintf(stderr, "Error: create child signalfd failed\n");
        exit(EXIT_FAILURE);
    }

    if (loop_init(&loop, &csig) == -1) {
        fprintf(stderr, "Error: init event loop module failed\n");
        exit(EXIT_FAILURE);
    }
    if (core_init(&core, loop, tunfd) == -1) {
        fprintf(stderr, "Error: init core lwIP forwarding module failed\n");
        exit(EXIT_FAILURE);
    }

    /* write a byte after initialization, notify that parent is ready */
    if (send(sk, &(char){ 0 }, sizeof(char), MSG_NOSIGNAL) == -1) {
        fprintf(stderr, "parent: child terminated unexpectedly\n");
        exit(EXIT_FAILURE);
    }
    close(sk);

    loginfo("parent: starting event loop");
    if ((loop_run(loop)) == -1) {
        fprintf(stderr, "Error: an error occurred in event loop\n");
        exit(EXIT_FAILURE);
    }

    core_deinit(core);
    loop_deinit(loop);
    close(csig.sigfd);
    close(tunfd);

    return csig.rc;
}

/* tasks in child process are:
   1. Enter a new net_namespace.
   2. Create a TUN device and configure networking.
   3. Send TUN file descriptor to parent process.
   4. Wait parent is ready to start.
   5. exec(2) target application. exec(2) ends the child process's lifecycle.
*/
static int child(int sk, char *cmd[])
{
    int tunfd;
    struct nspconf *conf = current_nspconf();

    unshare_net();

    unshare_mount();

    bringup_loopback();

    tunfd = bringup_tun();

    if (conf->ipv6)
        setup_ipv6();

    send_fd(sk, tunfd);

    /* wait for parent process to ready, avoid potential race conditions,
       prevent child process being terminated before sigprocmask is set */
    if (recv(sk, &(char){ 0 }, sizeof(char), 0) <= 0) {
        fprintf(stderr, "child: parent terminated unexpectedly\n");
        exit(EXIT_FAILURE);
    }
    close(sk);

    loginfo("child: execvp(\"%s\", ...)", cmd[0]);

    if (execvp(cmd[0], cmd) == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "nsproxy: Command not found: %s\n", cmd[0]);
            exit(EXIT_FAILURE);
        } else {
            perror("execvp()");
            exit(EXIT_FAILURE);
        }
    }

    /* never reach */
    return 0;
}

int main(int argc, char *argv[])
{
    int skpair[2];
    pid_t cid;
    int opt;
    struct nspconf conf = { 0 };
    const char *serv = NULL;
    const char *port = NULL;
    const char *dns = NULL;
    char *auth = NULL;
    int ishttp = 0, isdirect = 0;

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        printf("%s", nsproxy_help_message__);
        exit(EXIT_SUCCESS);
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s", nsproxy_version_message__);
        exit(EXIT_SUCCESS);
    }

    while ((opt = getopt(argc, argv, "+hVHDs:p:d:a:qv6")) != -1) {
        switch (opt) {
        case 'h':
            printf("%s", nsproxy_help_message__);
            exit(EXIT_SUCCESS);
        case 'V':
            printf("%s", nsproxy_version_message__);
            exit(EXIT_SUCCESS);
        case 'H':
            ishttp = 1;
            break;
        case 'D': /* un-documented feature */
            isdirect = 1;
            break;
        case '6':
            conf.ipv6 = 1;
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
        case 'a':
            auth = optarg;
            break;
        case 'v':
            nsproxy_verbose_level__++;
            break;
        case 'q':
            nsproxy_verbose_level__ = -255;
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "nsproxy: missing argument \"COMMAND\".\n");
        exit(EXIT_FAILURE);
    }

    if (serv == NULL)
        serv = "127.0.0.1";

    if (port == NULL)
        port = ishttp ? "8080" : "1080";

    if (dns == NULL)
        dns = "tcp://1.1.1.1";

    if (auth) {
        size_t ulen, plen;
        char *sep;

        if ((sep = strchr(auth, ':')) == NULL) {
            fprintf(stderr, "nsproxy: bad '-a' option, see '--help'\n");
            exit(EXIT_FAILURE);
        }

        ulen = sep - auth;
        plen = strlen(sep + 1);
        if (ulen == 0 || (plen == 0 && !ishttp)) {
            fprintf(stderr, "nsproxy: bad '-a' option, see '--help'\n");
            exit(EXIT_FAILURE);
        }
        if (ulen >= sizeof(conf.proxyuser) || plen >= sizeof(conf.proxypass)) {
            fprintf(stderr, "nsproxy: bad '-a' option: too long\n");
            exit(EXIT_FAILURE);
        }

        snprintf(conf.proxyuser, sizeof(conf.proxyuser), "%.*s", (int)ulen, auth);
        snprintf(conf.proxypass, sizeof(conf.proxypass), "%s", sep + 1);

        /* wipe plain text password that display in process name */
        memset(auth, '*', ulen + 1 + plen);
    }

    if (ishttp && isdirect) {
        fprintf(stderr, "nsproxy: can't use -H and -D together.\n");
        exit(EXIT_FAILURE);
    } else if (ishttp) {
        conf.proxytype = PROXY_HTTP;
    } else if (isdirect) {
        conf.proxytype = PROXY_DIRECT;
    } else {
        conf.proxytype = PROXY_SOCKS5;
    }

    if (!isdirect) {
        /* if server address is domain name, resolve to IP address at first */
        struct addrinfo hints = { .ai_family = AF_UNSPEC };
        struct addrinfo *result;
        if (getaddrinfo(serv, port, &hints, &result) != 0) {
            fprintf(stderr, "nsproxy: unsupported proxy server address.\n");
            exit(EXIT_FAILURE);
        }
        if (result->ai_family == AF_INET) {
            struct sockaddr_in *sa4 = (struct sockaddr_in *)result->ai_addr;
            inet_ntop(result->ai_family, &sa4->sin_addr, conf.proxysrv,
                      sizeof(conf.proxysrv));
            conf.proxyport = ntohs(sa4->sin_port);
        } else if (result->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)result->ai_addr;
            inet_ntop(result->ai_family, &sa6->sin6_addr, conf.proxysrv,
                      sizeof(conf.proxysrv));
            conf.proxyport = ntohs(sa6->sin6_port);
        } else {
            fprintf(stderr, "nsproxy: unsupported proxy server address.\n");
            exit(EXIT_FAILURE);
        }
        freeaddrinfo(result);
    }

    if (strcmp(dns, "off") == 0) {
        conf.dnstype = DNS_REDIR_OFF;
    } else if (strstr(dns, "tcp://") == dns || strstr(dns, "udp://") == dns) {
        const char *sv = dns + strlen("tcp://"); /* same size with "udp://" */
        const char *sep, *ipbegin, *ipend;
        size_t iplen;
        uint16_t port;

        /* parse ipbegin / ipend */
        if (sv[0] == '[') {
            /* [ipv6] or [ipv6_addr]:port */
            ipbegin = sv + 1;
            if ((ipend = strchr(ipbegin, ']')) == NULL) {
                fprintf(stderr, "nsproxy: bad '-d' option: invalid \"IP\"\n");
                exit(EXIT_FAILURE);
            }
            if (*(ipend + 1) != '\0' && *(ipend + 1) != ':') {
                fprintf(stderr, "nsproxy: bad '-d' option: invalid \"IP\"\n");
                exit(EXIT_FAILURE);
            }
            sep = strchr(ipend + 1, ':');
        } else {
            /* ipv4 / ipv4:port */
            ipbegin = sv;
            sep = strchr(sv, ':');
            if (sep != strrchr(sv, ':')) {
                fprintf(stderr, "nsproxy: bad '-d' option: IPv6 must be enclosed "
                                "in []\n");
                exit(EXIT_FAILURE);
            }
            ipend = sep ? sep : (sv + strlen(ipbegin));
        }

        /* check iplen */
        iplen = ipend - ipbegin;
        if (iplen == 0 || iplen > IP_MAXLEN) {
            fprintf(stderr, "nsproxy: bad '-d' option: invalid \"IP\"\n");
            exit(EXIT_FAILURE);
        }

        /* parse port */
        if (sep) {
            char *endptr;
            long val = strtol(sep + 1, &endptr, 10);
            if (val <= 0 || val > 65535 || *endptr != '\0') {
                fprintf(stderr, "nsproxy: bad '-d' option: invalid \"PORT\"\n");
                exit(EXIT_FAILURE);
            }
            port = val;
        } else {
            port = 53;
        }

        snprintf(conf.dnssrv, sizeof(conf.dnssrv), "%.*s", (int)iplen, ipbegin);
        conf.dnsport = port;
        conf.dnstype = dns[0] == 't' ? DNS_REDIR_TCP : DNS_REDIR_UDP;
    } else {
        fprintf(stderr, "nsproxy: bad '-d' option, see '--help'\n");
        exit(EXIT_FAILURE);
    }

    current_nspconf() = &conf;

    /* command line config initialized, print it */
    if (nsproxy_verbose_level__ >= 0) {
        char dispserv[SERVNAME_MAXLEN + 128] = { 0 };
        char dispdns[SERVNAME_MAXLEN + 128] = { 0 };

        if (conf.proxytype == PROXY_SOCKS5)
            snprintf(dispserv, sizeof(dispserv), "socks5://%s:%u",
                     conf.proxysrv, (unsigned)conf.proxyport);
        else if (conf.proxytype == PROXY_HTTP)
            snprintf(dispserv, sizeof(dispserv), "http://%s:%u",
                     conf.proxysrv, (unsigned)conf.proxyport);
        else
            strcpy(dispserv, "(direct)");

        if (conf.dnstype == DNS_REDIR_TCP)
            snprintf(dispdns, sizeof(dispdns), "tcp://%s:%u",
                     conf.dnssrv, (unsigned)conf.dnsport);
        else if (conf.dnstype == DNS_REDIR_UDP)
            snprintf(dispdns, sizeof(dispdns), "udp://%s:%u", 
                     conf.dnssrv, (unsigned)conf.dnsport);
        else
            strcpy(dispdns, "(off)");

        loglv0("Proxy Server:     %s", dispserv);
        loglv0("DNS Redirection:  %s", dispdns);
        loglv0("Verbose:          %s",
               nsproxy_verbose_level__ > 0 ? "yes" : "no");
    }

    /* main */
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, skpair) == -1) {
        perror("socketpair()");
        exit(EXIT_FAILURE);
    }

    if ((cid = fork()) == -1) {
        perror("fork()");
        exit(EXIT_FAILURE);
    }

    if (cid) {
        loginfo("parent: forked child process (pid=%d)", cid);
        close(skpair[1]);
        return parent(skpair[0], cid);
    } else {
        loginfo("child: process started");
        close(skpair[0]);
        return child(skpair[1], argv + optind);
    }
}

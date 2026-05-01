#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "loop.h"
#include "core.h"
#include "lwipopts.h"

int nsproxy_verbose_level__ = 0;
struct nspconf *nsproxy_current_nspconf__ = NULL;

static void print_help(void)
{
    printf("usage: \n"
           "  nsproxy [-h] [-H] [-s <server>] [-p <port>] [-d <dns>] [-a <user:password>] [-v|-q] "
           "<command>\n"
           "options:\n"
           "  -h\n"
           "    Print this help message and exit.\n"
           "  -H\n"
           "    Use http proxy, not socks5.\n"
           "  -s <server>\n"
           "    Proxy server address.\n"
           "  -p <port>\n"
           "    Proxy server port.\n"
           "  -d <dns>\n"
           "    DNS redirect, allow following options:\n"
           "      -d off\n"
           "        Do nothings on DNS, treat as normal UDP packets.\n"
           "      -d tcp://<server_ip>[:port]\n"
           "        Redirect DNS requests to specified TCP nameserver.\n"
           "      -d udp://<server_ip>[:port]\n"
           "        Redirect DNS requests to specified UDP nameserver.\n"
           "  -a <user:password>\n"
           "    Proxy authentication (SOCKS5 or HTTP Basic Auth).\n"
           "  -6\n"
           "    Enable IPv6 support.\n"
           "  -v\n"
           "    Verbose mode. Use \"-vv\" or \"-vvv\" for more verbose.\n"
           "  -q\n"
           "    Be quiet.\n");
}

static int write_string(const char *fname, const char *str)
{
    int fd;

    if ((fd = open(fname, O_WRONLY | O_APPEND | O_CLOEXEC)) == -1) {
        return -errno;
    }

    if (write(fd, str, strlen(str)) == -1) {
        close(fd);
        return -errno;
    }

    close(fd);
    return 0;
}

static void map_uid(unsigned int from, unsigned int to)
{
    int ret;
    char str[32];

    snprintf(str, sizeof(str), "%u %u 1\n", from, to);
    ret = write_string("/proc/self/uid_map", str);

    if (ret < 0) {
        fprintf(stderr, "nsproxy: map_uid() failed: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }
}

static void map_gid(unsigned int from, unsigned int to)
{
    int ret;
    char str[32];

    snprintf(str, sizeof(str), "%u %u 1\n", from, to);
    ret = write_string("/proc/self/gid_map", str);

    if (ret < 0) {
        fprintf(stderr, "nsproxy: map_gid() failed: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }
}

static void set_setgroups(const char *action)
{
    int ret = write_string("/proc/self/setgroups", action);

    if (ret < 0) {
        fprintf(stderr,
                "nsproxy: set groups failed: %s\n"
                "hints: If you are using Ubuntu >= 23.10, add the following "
                "content to /etc/sysctl.d/70-apparmor-userns.conf\n"
                "    kernel.apparmor_restrict_unprivileged_userns=0\n"
                "then run command (with root)\n"
                "    sysctl -p /etc/sysctl.d/70-apparmor-userns.conf\n",
                strerror(-ret));
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
    if ((tunfd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) == -1) {
        if (errno == ENOENT) {
            fprintf(stderr,
                    "nsproxy: open \"/dev/net/tun\" failed.\n"
                    "hints: If you are using OpenWrt, install the package "
                    "'kmod-tun'.\n"
                    "       If you are using LXC, add device '/dev/tun' "
                    "to container.\n");
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
    inet_pton(AF_INET, NSPROXY_GATEWAY_IP, &sai->sin_addr);
    if (ioctl(sk, SIOCGIFDSTADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFDSTADDR)");
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

    loglv(3, "child: brought up tun device and configured IPv4");

    close(sk);
    return tunfd;
}

static void setup_ipv6(void)
{
    int sk;
    struct ifreq ifr = { .ifr_name = "tun0" };
    struct in6_ifreq ifr6 = {0};
    struct in6_rtmsg rtmsg6 = {0};

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
    rtmsg6.rtmsg_dst_len = 0;  /* ::/0 */
    rtmsg6.rtmsg_src_len = 0;
    rtmsg6.rtmsg_metric = 1;
    rtmsg6.rtmsg_flags = RTF_UP | RTF_GATEWAY;
    rtmsg6.rtmsg_ifindex = ifr.ifr_ifindex;

    if (ioctl(sk, SIOCADDRT, &rtmsg6) < 0) {
        perror("ioctl(SIOCADDRT) IPv6");
        exit(EXIT_FAILURE);
    }

    loglv(3, "child: configured IPv6");
    close(sk);
}

/* create mount namespace, and make it isolate really */
static int unshare_mount(void)
{
    if (unshare(CLONE_NEWNS) == -1)
        goto failed;
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1)
        goto failed;
    return 0;

failed:
    loglv(0, "Warning: Unshare mount namespace failed. "
             "DNS redirect may not work.");
    return -1;
}

static void configure_resolv_conf(void)
{
    int fd;
    char path[] = "/tmp/nsproxy-resolv-conf-XXXXXX";
    const char *content = "nameserver " NSPROXY_GATEWAY_IP "\n";

    if ((fd = mkstemp(path)) == -1)
        goto failed_on_create;

    if (chmod(path, 0644) == -1)
        goto failed_after_create;

    if (write(fd, content, strlen(content)) == -1)
        goto failed_after_create;

    if (mount(path, "/etc/resolv.conf", NULL, MS_BIND | MS_RDONLY, NULL) == -1)
        goto failed_after_create;

    loglv(3, "child: re-bound /etc/resolv.conf");

    close(fd);
    unlink(path);
    return;

failed_after_create:
    close(fd);
    unlink(path);
failed_on_create:
    loglv(0, "Warning: re-bind /etc/resolv.conf failed. "
             "DNS redirect may not work.");
}

static void configure_nsswitch_conf(void)
{
    int fd;
    char path[] = "/tmp/nsproxy-nsswitch-conf-XXXXXX";
    const char *content = "hosts: files dns\n";

    if ((fd = mkstemp(path)) == -1)
        goto failed_on_create;

    if (chmod(path, 0644) == -1)
        goto failed_after_create;

    if (write(fd, content, strlen(content)) == -1)
        goto failed_after_create;

    if (mount(path, "/etc/nsswitch.conf", NULL, MS_BIND | MS_RDONLY, NULL) ==
        -1)
        goto failed_after_create;

    loglv(3, "child: re-bound /etc/nsswitch.conf");

    close(fd);
    unlink(path);
    return;

failed_after_create:
    close(fd);
    unlink(path);
failed_on_create:
    loglv(0, "Warning: re-bind /etc/nsswitch.conf failed. "
             "DNS redirect may not work.");
}

/* send a file descriptor to sock
   must succeed, otherwise terminate this process */
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
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    if (sendmsg(sock, &msg, 0) == -1) {
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
        exit(EXIT_FAILURE);
    }
    if (nrecv == 0) {
        exit(EXIT_FAILURE);
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
        fprintf(stderr, "nsproxy: empty cmsg in recv_fd()\n");
        exit(EXIT_FAILURE);
    }

    memcpy(&ret, CMSG_DATA(cmsg), sizeof(ret));
    return ret;
}

/* tasks in parent process are:
   1. Receive TUN file descriptor from child process.
   2. Start event loop, the event loop will handle IP packets from TUN
      device and forward traffic to proxy server.
*/
static int parent(int sk)
{
    int rc, tunfd, chdsigfd;
    sigset_t mask;
    struct loopctx *loop;
    struct corectx *core;
    char dummy = '\0';

    /* become a subreaper, receive SIGCHLD for grandchilds */
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1) {
        loglv(0, "Warning: Failed to set child subreaper, "
                 "grandchild processes may not be tracked.");
    }

    tunfd = recv_fd(sk);

    if (sigemptyset(&mask) == -1) {
        perror("sigemptyset()");
        exit(EXIT_FAILURE);
    }
    if (sigaddset(&mask, SIGCHLD) == -1) {
        perror("sigaddset()");
        exit(EXIT_FAILURE);
    }
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        perror("sigprocmask()");
        exit(EXIT_FAILURE);
    }

    if ((chdsigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK)) == -1) {
        perror("signalfd()");
        exit(EXIT_FAILURE);
    }

    /* write a byte after sigmask is set, indicate set up completely */
    if (write(sk, &dummy, sizeof(dummy)) == -1) {
        perror("write()");
        exit(EXIT_FAILURE);
    }
    close(sk);

    loop_init(&loop, chdsigfd);
    core_init(&core, loop, tunfd);

    loglv(3, "parent: starting event loop");
    rc = loop_run(loop);

    core_deinit(core);
    loop_deinit(loop);
    close(chdsigfd);
    close(tunfd);

    return rc;
}

/* tasks in child process are:
   1. Enter a new net_namespace.
   2. Create a TUN device and configure networking.
   3. Send TUN file descriptor to parent process.
   4. exec(2) target application.
*/
static int child(int sk, char *cmd[])
{
    int tunfd;
    char dummy;
    uid_t uid, gid;
    struct nspconf *conf = current_nspconf();

    if (unshare(CLONE_NEWNET) == -1) {
        if (errno == ENOSYS || errno == EINVAL) {
            fprintf(stderr, "nsproxy: create net_namespace failed.\n"
                            "nsproxy: This kernel may not have net_namespace "
                            "support enabled.\n");
            exit(EXIT_FAILURE);
        }

        /* Failed, of cause. Unprivileged users can't create net_namespace.
           Try again with user_namespace */
        uid = getuid();
        gid = getgid();

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

        loglv(3, "child: created user and net namespace");

        set_setgroups("deny");

        map_uid(uid, uid);
        map_gid(gid, gid);
    } else {
        loglv(3, "child: created net namespace");
    }

    if (unshare_mount() == 0) {
        loglv(3, "child: created mount namespace");

        /* WORKAROUND: Bad owner or permissions on /etc/ssh/ssh_config.d */
        mount("tmpfs", "/etc/ssh/ssh_config.d", "tmpfs", 0, NULL);

        /* ensure DNS redirection work */
        if (conf->dnstype != DNS_REDIR_OFF) {
            configure_resolv_conf();
            configure_nsswitch_conf();
        }
    }

    bringup_loopback();

    tunfd = bringup_tun();

    if (conf->ipv6)
        setup_ipv6();

    send_fd(sk, tunfd);

    /* wait for parent process to set sigmask,
       prevent child process being terminated before sigmask is set  */
    if (read(sk, &dummy, sizeof(dummy)) == -1) {
        perror("read()");
        exit(EXIT_FAILURE);
    }

    close(sk);

    loglv(3, "child: execvp(\"%s\", ...)", cmd[0]);

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
        print_help();
        exit(EXIT_SUCCESS);
    }

    while ((opt = getopt(argc, argv, "+hHDs:p:d:a:qv6")) != -1) {
        switch (opt) {
        case 'h':
            print_help();
            exit(EXIT_SUCCESS);
        case 'H':
            ishttp = 1;
            break;
        case 'D':
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
        fprintf(stdout, "nsproxy: missing argument \"command\".\n");
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
            fprintf(stderr, "nsproxy: invalid auth argument, expected "
                            "<user>:<password>\n");
            exit(EXIT_FAILURE);
        }
        ulen = sep - auth;
        plen = strlen(sep + 1);
        if (ulen >= sizeof(conf.proxyuser) || plen >= sizeof(conf.proxypass)) {
            fprintf(stderr, "nsproxy: username or password too long\n");
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
            conf.proxyport = be16toh(sa4->sin_port);
        } else if (result->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)result->ai_addr;
            inet_ntop(result->ai_family, &sa6->sin6_addr, conf.proxysrv,
                      sizeof(conf.proxysrv));
            conf.proxyport = be16toh(sa6->sin6_port);
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
        int port;

        if (sv[0] == '[') {
            /* [ipv6] or [ipv6_addr]:port */
            ipbegin = sv + 1;
            if ((ipend = strchr(ipbegin, ']')) == NULL) {
                fprintf(stderr, "nsproxy: Bad DNS server address\n");
                exit(EXIT_FAILURE);
            }
            sep = strchr(ipend, ':');
        } else {
            /* ipv4 / ipv4:port */
            ipbegin = sv;
            sep = strchr(sv, ':');
            if (sep != strrchr(sv, ':')) {
                fprintf(stderr, "nsproxy: IPv6 DNS must be enclosed in []\n");
                exit(EXIT_FAILURE);
            }
            ipend = sep ? sep : (sv + strlen(ipbegin));
        }

        iplen = ipend - ipbegin;
        if (iplen == 0 || iplen > SERVNAME_MAXLEN) {
            fprintf(stderr, "nsproxy: Bad DNS server address\n");
            exit(EXIT_FAILURE);
        }

        port = sep ? atoi(sep + 1) : 53;
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "nsproxy: Bad DNS server port\n");
            exit(EXIT_FAILURE);
        }

        snprintf(conf.dnssrv, sizeof(conf.dnssrv), "%.*s", (int)iplen, ipbegin);
        conf.dnsport = port;
        conf.dnstype = dns[0] == 't' ? DNS_REDIR_TCP : DNS_REDIR_UDP;
    } else {
        fprintf(stderr, "nsproxy: unsupported dns server address.\n");
        exit(EXIT_FAILURE);
    }

    if (strlen(conf.dnssrv) == sizeof(conf.dnssrv) - 1) {
        fprintf(stderr, "nsproxy: dns server address too long.\n");
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
            snprintf(dispdns, sizeof(dispdns), "tcp://%s", conf.dnssrv);
        else if (conf.dnstype == DNS_REDIR_UDP)
            snprintf(dispdns, sizeof(dispdns), "udp://%s", conf.dnssrv);
        else
            strcpy(dispdns, "(off)");

        loglv(0, "Proxy Server:     %s", dispserv);
        loglv(0, "DNS Redirection:  %s", dispdns);
        loglv(0, "Verbose:          %s",
              nsproxy_verbose_level__ > 0 ? "yes" : "no");
    }

    /* main */
    if (socketpair(AF_UNIX, SOCK_STREAM | SFD_CLOEXEC, 0, skpair) == -1) {
        perror("socketpair()");
        exit(EXIT_FAILURE);
    }

    if ((cid = fork()) == -1) {
        perror("fork()");
        exit(EXIT_FAILURE);
    }

    if (cid) {
        loglv(3, "parent: forked child process (pid=%d)", cid);
        close(skpair[1]);
        return parent(skpair[0]);
    } else {
        loglv(3, "child: process started");
        close(skpair[0]);
        return child(skpair[1], argv + optind);
    }
}

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"
#include "loop.h"
#include "lwip/opt.h"

int nsproxy_verbose_level__ = 0;

static void print_help(void)
{
    printf("usage: \n"
           "  nsproxy [-H] [-s <server>] [-p <port>] [-d <dns>] [-v|-q] "
           "<command>\n"
           "options:\n"
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
           "      -d tcp://<nameserver_ipaddress>\n"
           "        Redirect DNS requests to specified TCP nameserver.\n"
           "      -d udp://<nameserver_ipaddress>\n"
           "        Redirect DNS requests to specified UDP nameserver.\n"
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
        abort();
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
        abort();
    }
}

static void set_setgroups(const char *action)
{
    int ret = write_string("/proc/self/setgroups", action);

    if (ret < 0) {
        fprintf(stderr, "nsproxy: set groups failed: %s\n", strerror(-ret));
        abort();
    }
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
        if (errno == ENOENT) {
            fprintf(stderr, "nsproxy: open \"/dev/net/tun\" failed.\n"
                            "nsproxy: This kernel may not have TUN device "
                            "support enabled.\n");
            exit(EXIT_FAILURE);
        } else {
            perror("open()");
            abort();
        }
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

static void configure_hosts_conf(void)
{
    int fd;
    char path[] = "/tmp/nsproxy-hosts-conf-XXXXXX";
    const char *content = "127.0.0.1 localhost\n";

    if ((fd = mkstemp(path)) == -1)
        goto failed_on_create;

    if (chmod(path, 0644) == -1)
        goto failed_after_create;

    if (write(fd, content, strlen(content)) == -1)
        goto failed_after_create;

    if (mount(path, "/etc/hosts", NULL, MS_BIND | MS_RDONLY, NULL) ==
        -1)
        goto failed_after_create;

    close(fd);
    unlink(path);
    return;

failed_after_create:
    close(fd);
    unlink(path);
failed_on_create:
    loglv(0, "Warning: re-bind /etc/hosts failed. "
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
        abort();
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
        abort();
    }
    if (nrecv == 0) {
        exit(EXIT_FAILURE);
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS) {
        exit(EXIT_FAILURE);
    }

    memcpy(&ret, CMSG_DATA(cmsg), sizeof(ret));
    return ret;
}

/* tasks in parent process is:
   1. Receive TUN file descriptor from child process.
   2. Start event loop, the event loop will handle IP packets from TUN
      device and forward traffic to proxy server.
*/
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

    if (nsproxy_verbose_level__ >= 0) {
        char const *ptype, *dnsenabled, *dnsserv, *dnscomment;

        if (conf->proxytype == PROXY_SOCKS5)
            ptype = ", SOCKS";
        else if (conf->proxytype == PROXY_HTTP)
            ptype = ", HTTP";
        else
            ptype = "(none)";

        if (conf->dnstype == DNS_REDIR_OFF) {
            dnsenabled = "Disabled";
            dnsserv = dnscomment = "";
        } else if (conf->dnstype == DNS_REDIR_TCP) {
            dnsenabled = "Enabled, ";
            dnsserv = conf->dnssrv;
            dnscomment = ", TCP";
        } else {
            dnsenabled = "Enabled, ";
            dnsserv = conf->dnssrv;
            dnscomment = ", UDP";
        }

        loglv(0, "Proxy Server:       %s:%s%s", conf->proxysrv, conf->proxyport,
              ptype);
        loglv(0, "DNS Redirection:    %s%s%s", dnsenabled, dnsserv, dnscomment);
        loglv(0, "Verbose:            %s",
              nsproxy_verbose_level__ > 0 ? "Yes" : "No");
    }

    /* write a byte after sigmask is set, indicate set up completely */
    if (write(sk, &dummy, sizeof(dummy)) == -1) {
        perror("write()");
        abort();
    }

    close(sk);

    loop_init(&loop, conf, tunfd, childfd);
    return loop_run(loop);
}

/* tasks in child process is:
   1. Enter a new net_namespace.
   2. Create a TUN device and configure networking.
   3. Send TUN file descriptor to parent process.
   4. exec(2) target application.
*/
static int child(int sk, struct loopconf *conf, char *cmd[])
{
    int tunfd;
    char dummy;
    uid_t uid, gid;

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
                    "nsproxy: nsproxy can't run on this system.\n",
                    strerror(errno));
            exit(EXIT_FAILURE);
        }

        set_setgroups("deny");

        map_uid(uid, uid);
        map_gid(gid, gid);
    }

    /* return value is not checked, failure is allowed. */
    write_string("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");

    if (conf->dnstype != DNS_REDIR_OFF) {
        if (unshare_mount() == 0) {
            configure_hosts_conf();
            configure_resolv_conf();
            configure_nsswitch_conf();
        }
    }

    bringup_loopback();

    tunfd = bringup_tun();

    send_fd(sk, tunfd);

    /* wait for parent process to set sigmask,
       prevent child process being terminated before sigmask is set  */
    if (read(sk, &dummy, sizeof(dummy)) == -1) {
        perror("read()");
        abort();
    }

    close(sk);

    if (execvp(cmd[0], cmd) == -1) {
        if (errno == ENOENT) {
            fprintf(stderr, "nsproxy: command not found: %s\n", cmd[0]);
            exit(EXIT_FAILURE);
        } else {
            perror("execvp()");
            abort();
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
    struct addrinfo hints = { .ai_family = AF_UNSPEC };
    struct addrinfo *result;
    struct loopconf conf = { 0 };
    const char *serv = NULL;
    const char *port = NULL;
    const char *dns = NULL;
    int ishttp = 0, isdirect = 0;

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_help();
        exit(EXIT_SUCCESS);
    }

    while ((opt = getopt(argc, argv, "+HDs:p:d:qv")) != -1) {
        switch (opt) {
        case 'H':
            ishttp = 1;
            break;
        case 'D':
            isdirect = 1;
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

    /* if server address is domain name, resolve to IP address at first */
    if (getaddrinfo(serv, port, &hints, &result) != 0) {
        fprintf(stderr, "nsproxy: unsupported proxy server address.\n");
        exit(EXIT_FAILURE);
    }
    if (result->ai_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)result->ai_addr;
        inet_ntop(result->ai_family, &sa4->sin_addr, conf.proxysrv,
                  sizeof(conf.proxysrv));
        snprintf(conf.proxyport, sizeof(conf.proxyport), "%u",
                 (unsigned int)be16toh(sa4->sin_port));
    } else if (result->ai_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)result->ai_addr;
        inet_ntop(result->ai_family, &sa6->sin6_addr, conf.proxysrv,
                  sizeof(conf.proxysrv));
        snprintf(conf.proxyport, sizeof(conf.proxyport), "%u",
                 (unsigned int)be16toh(sa6->sin6_port));
    } else {
        fprintf(stderr, "nsproxy: unsupported proxy server address.\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);

    if (strcmp(dns, "off") == 0) {
        conf.dnstype = DNS_REDIR_OFF;
    } else if (strstr(dns, "tcp://") == dns) {
        conf.dnstype = DNS_REDIR_TCP;
        strncpy(conf.dnssrv, dns + strlen("tcp://"), sizeof(conf.dnssrv) - 1);
    } else if (strstr(dns, "udp://") == dns) {
        conf.dnstype = DNS_REDIR_UDP;
        strncpy(conf.dnssrv, dns + strlen("udp://"), sizeof(conf.dnssrv) - 1);
    } else {
        fprintf(stderr, "nsproxy: unsupported dns server address.\n");
        exit(EXIT_FAILURE);
    }

    if (strlen(conf.dnssrv) == sizeof(conf.dnssrv) - 1) {
        fprintf(stderr, "nsproxy: dns server address too long.\n");
        exit(EXIT_FAILURE);
    }

    /* main */
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
        return child(skpair[1], &conf, argv + optind);
    }
}

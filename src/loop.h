#pragma once
#include "common.h"

struct loopctx;

enum {
    DNS_REDIR_OFF,
    DNS_REDIR_DIRECT,
    DNS_REDIR_TCP,
    DNS_REDIR_UDP
};

enum {
    PROXY_SOCKS5,
    PROXY_HTTP,
    PROXY_DIRECT
};

struct loopconf {
    char proxysrv[64];
    char proxyport[8];
    uint8_t proxytype;
    char dnssrv[128];
    uint8_t dnstype;
};

void loop_init(struct loopctx **loop, struct loopconf *conf, int tunfd,
               int sigfd);
void loop_deinit(struct loopctx *loop);
int loop_run(struct loopctx *loop);
int loop_epfd(struct loopctx *loop);
struct loopconf *loop_conf(struct loopctx *loop);

/* A pointer to struct sk_ops representing a connection.

   Call "*_create()" function to obtain this pointer, and call methods via
   funcion pointers that included in struct sk_ops

   Passing this pointer back as first argument is required.
 */
struct sk_ops {
    /* connect funcion.
       argument addr should pointing to a string,
       should call this funcion before sending or receiving data,
    */
    int (*connect)(struct sk_ops *conn, const char *addr, uint16_t port);

    /* shutdown function
       argument how is same as shutdown(2), mostly used for TCP half-close
     */
    int (*shutdown)(struct sk_ops *conn, int how);

    /* event control funcion
       argument event is same as epoll_ctl(2)
       argument enable indicate bits contain in event should be set or unset
    */
    void (*evctl)(struct sk_ops *conn, unsigned int event, int enable);

    /* send funcion
       return number of bytes sent, or -errno on error
    */
    ssize_t (*send)(struct sk_ops *conn, const char *data, size_t len);

    /* send funcion
       return number of bytes read, or -errno on error
    */
    ssize_t (*recv)(struct sk_ops *conn, char *data, size_t len);

    /* destory funcion
       release all resources including memory
       should call this funcion if a EPOLLERR occured in usercallback
       call to shudown before destory is not required
    */
    void (*destroy)(struct sk_ops *conn);
};

struct ep_poller {
    void (*on_epoll_event)(struct ep_poller *poller, unsigned int event);
};

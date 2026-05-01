#pragma once
#include "common.h"

struct proxy;

struct proxy_ops {
    int (*shutdown)(struct proxy *proxy, int how, int rst);
    int (*evctl)(struct proxy *proxy, unsigned int events, int enable);
    ssize_t (*send)(struct proxy *proxy, const char *data, size_t len);
    ssize_t (*recv)(struct proxy *proxy, char *data, size_t len);
    void (*get)(struct proxy *proxy);
    void (*put)(struct proxy *proxy);
};

/* A pointer to `struct proxy' representing a proxy connection,
   call `*_create()' function to obtain this pointer
 */
struct proxy {
    struct proxy_ops const *ops;
};

/* shutdown function
   argument how is same as shutdown(2), mostly used for TCP half-close
*/
static inline int proxy_shutdown(struct proxy *proxy, int how, int rst)
{
    return proxy->ops->shutdown(proxy, how, rst);
}

/* event control funcion
   argument events is same as epoll_ctl(2)
   argument enable indicate bits contain in event should be set or unset
*/
static inline int proxy_evctl(struct proxy *proxy, unsigned int events,
                               int enable)
{
    return proxy->ops->evctl(proxy, events, enable);
}

/* send funcion
   return number of bytes sent, or -errno on error
*/
static inline ssize_t proxy_send(struct proxy *proxy, const char *data,
                                 size_t len)
{
    return proxy->ops->send(proxy, data, len);
}

/* send funcion
   return number of bytes read, or -errno on error
*/
static inline ssize_t proxy_recv(struct proxy *proxy, char *data, size_t len)
{
    return proxy->ops->recv(proxy, data, len);
}

/* get funcion
   increase reference count of this connection
 */
static inline void proxy_get(struct proxy *proxy)
{
    proxy->ops->get(proxy);
}

/* put funcion
   decrease reference count of this connection
 */
static inline void proxy_put(struct proxy *proxy)
{
    proxy->ops->put(proxy);
}

/* events callback function
   called when events occurs on this connection
 */
typedef void (userev_fn_t)(void *userp, unsigned int events);

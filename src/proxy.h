#pragma once
#include "common.h"

struct proxy;

struct proxy_ops {
    int (*shutdown)(struct proxy *proxy, int how, int rst);
    int (*evctl)(struct proxy *proxy, unsigned int events, int mode);
    ssize_t (*send)(struct proxy *proxy, const char *data, size_t len);
    ssize_t (*recv)(struct proxy *proxy, char *data, size_t len);
    void (*get)(struct proxy *proxy);
    void (*put)(struct proxy *proxy);
};

/* A pointer to `struct proxy' representing a proxy connection,
   call `*_create()' function to obtain this pointer
 */
struct proxy {
    const struct proxy_ops *ops;
};

/* evctl mode:
   - EVCLR: bits-clear, remove those events from interest mask
   - EVSET: bits-set, add those events to interest mask
   - EVUPD: update, assign interest mask
*/
enum {
    EVCLR = 0,
    EVSET = 1,
    EVUPD = 2,
};

/* shutdown function
   'how' is same as shutdown(2), mostly used for TCP half-close
   if 'rst' set, the connection will be forcefully closed.
   return 0 if no error, or -errno if error
*/
static inline int proxy_shutdown(struct proxy *proxy, int how, int rst)
{
    return proxy->ops->shutdown(proxy, how, rst);
}

/* event control function
   'events' is same as epoll_ctl(2)
   'mode' see 'evctl mode'
   return 0 if no error, or -errno if error
*/
static inline int proxy_evctl(struct proxy *proxy, unsigned int events, int mode)
{
    return proxy->ops->evctl(proxy, events, mode);
}

/* send function
   return number of bytes sent, or -errno on error
*/
static inline ssize_t proxy_send(struct proxy *proxy, const char *data,
                                 size_t len)
{
    return proxy->ops->send(proxy, data, len);
}

/* send function
   return number of bytes read, or -errno on error
*/
static inline ssize_t proxy_recv(struct proxy *proxy, char *data, size_t len)
{
    return proxy->ops->recv(proxy, data, len);
}

/* get function
   increase reference count of this connection
 */
static inline void proxy_get(struct proxy *proxy)
{
    proxy->ops->get(proxy);
}

/* put function
   decrease reference count of this connection
 */
static inline void proxy_put(struct proxy *proxy)
{
    proxy->ops->put(proxy);
}

/* events callback function
   called when events occurs on this connection
   'events' is same as epoll_wait(2)
 */
typedef void (userev_fn_t)(void *userp, unsigned int events);

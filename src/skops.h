#pragma once
#include "common.h"

/* A pointer to struct sk_ops representing a proxy connection.

   Call "*_create()" function to obtain this pointer, and call methods via
   funcion pointers that included in struct sk_ops

   Passing this pointer back as first argument is required.
 */
struct sk_ops {
    /* shutdown function
       argument how is same as shutdown(2), mostly used for TCP half-close
     */
    int (*shutdown)(struct sk_ops *conn, int how, int rst);

    /* event control funcion
       argument events is same as epoll_ctl(2)
       argument enable indicate bits contain in event should be set or unset
    */
    void (*evctl)(struct sk_ops *conn, unsigned int events, int enable);

    /* send funcion
       return number of bytes sent, or -errno on error
    */
    ssize_t (*send)(struct sk_ops *conn, const char *data, size_t len);

    /* send funcion
       return number of bytes read, or -errno on error
    */
    ssize_t (*recv)(struct sk_ops *conn, char *data, size_t len);

    /* get funcion
       increase reference count of this connection
     */
    void (*get)(struct sk_ops *conn);

    /* put funcion
       decrease reference count of this connection
       release all resources including memory if refcnt reaches zero
       should call this funcion if a EPOLLERR occured in usercallback
       call to shutdown before put is not required
     */
    void (*put)(struct sk_ops *conn);
};

/* events callback function
   called when events occurs on this connection
 */
typedef void (userev_fn_t)(void *userp, unsigned int events);

#pragma once

#ifndef __GNUC__
#error "Only support GNU C compiler"
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

#define arraysizeof(array) (sizeof(array) / sizeof(*(array)))

#define is_ignored_skerr(err)                                          \
    ((err) == ECONNRESET || (err) == ECONNREFUSED || (err) == EPIPE || \
     (err) == ETIMEDOUT || (err) == EINPROGRESS || (err) == EAGAIN ||  \
     (err) == ENOTCONN)

#define loglv(lv, str, ...)                                        \
    do {                                                           \
        if (nsproxy_verbose_level__ >= lv)                         \
            fprintf(stderr, "[nsproxy] " str "\n", ##__VA_ARGS__); \
    } while (0)

#define current_nspconf() (nsproxy_current_nspconf__)

#ifndef static_assert
#if defined(__GNUC__) && (__GNUC__ > 4)
#define static_assert(cond, msg) __extension__ _Static_assert(cond, msg)
#else
#define static_assert(cond, msg)
#endif
#endif

enum {
    DNS_REDIR_OFF,
    DNS_REDIR_TCP,
    DNS_REDIR_UDP
};

enum {
    PROXY_SOCKS5,
    PROXY_HTTP,
    PROXY_DIRECT
};

struct nspconf {
    char proxysrv[64];
    char proxyport[8];
    uint8_t proxytype;
    char dnssrv[128];
    uint8_t dnstype;
    char proxyuser[64];   /* Proxy username for authentication */
    char proxypass[64];   /* Proxy password for authentication */
};


extern int nsproxy_verbose_level__;
extern struct nspconf *nsproxy_current_nspconf__;

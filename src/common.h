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

extern int nsproxy_verbose_level__;

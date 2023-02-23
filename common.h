#pragma once

#ifndef __GNUC__
#error "Only support GNU C compiler"
#endif

#define container_of(ptr, type, member)                    \
    ({                                                     \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); \
    })

#define CONFIG_LOCAL_IP   "172.23.255.255"
#define CONFIG_GATEWAY_IP "172.23.255.254"
#define CONFIG_NETMASK    "255.255.255.254"
#define CONFIG_MTU 1500

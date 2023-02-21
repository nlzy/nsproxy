/*
   Copyright (C) 2018 Free Software Foundation, Inc.
   Written by Joan Lledó.

   This file is part of the GNU Hurd.

   The GNU Hurd is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   The GNU Hurd is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with the GNU Hurd. If not, see <http://www.gnu.org/licenses/>.  */

#ifndef HURD_LWIP_POSIX_INET_H
#define HURD_LWIP_POSIX_INET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_IPV4

#define inet_addr_from_ip4addr(target_inaddr, source_ipaddr) ((target_inaddr)->s_addr = ip4_addr_get_u32(source_ipaddr))
#define inet_addr_to_ip4addr(target_ipaddr, source_inaddr)   (ip4_addr_set_u32(target_ipaddr, (source_inaddr)->s_addr))

#ifdef LWIP_UNIX_HURD
#define IP_PKTINFO  8

struct in_pktinfo {
  unsigned int   ipi_ifindex;  /* Interface index */
  struct in_addr ipi_addr;     /* Destination (from header) address */
};
#endif /* LWIP_UNIX_HURD */

#endif /* LWIP_IPV4 */

#if LWIP_IPV6
#define inet6_addr_from_ip6addr(target_in6addr, source_ip6addr) {(target_in6addr)->s6_addr32[0] = (source_ip6addr)->addr[0]; \
                                                                 (target_in6addr)->s6_addr32[1] = (source_ip6addr)->addr[1]; \
                                                                 (target_in6addr)->s6_addr32[2] = (source_ip6addr)->addr[2]; \
                                                                 (target_in6addr)->s6_addr32[3] = (source_ip6addr)->addr[3];}
#define inet6_addr_to_ip6addr(target_ip6addr, source_in6addr)   {(target_ip6addr)->addr[0] = (source_in6addr)->s6_addr32[0]; \
                                                                 (target_ip6addr)->addr[1] = (source_in6addr)->s6_addr32[1]; \
                                                                 (target_ip6addr)->addr[2] = (source_in6addr)->s6_addr32[2]; \
                                                                 (target_ip6addr)->addr[3] = (source_in6addr)->s6_addr32[3]; \
                                                                 ip6_addr_clear_zone(target_ip6addr);}
/* ATTENTION: the next define only works because both in6_addr and ip6_addr_t are an u32_t[4] effectively! */
#define inet6_addr_to_ip6addr_p(target_ip6addr_p, source_in6addr)   ((target_ip6addr_p) = (ip6_addr_t*)(source_in6addr))
#endif /* LWIP_IPV6 */

#ifdef __cplusplus
}
#endif

#endif /* HURD_LWIP_POSIX_INET_H */

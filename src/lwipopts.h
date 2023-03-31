#pragma once

#define NO_SYS       1
#define LWIP_SOCKET  0
#define LWIP_NETCONN 0

/* Enable modules */
#define LWIP_ARP      0
#define LWIP_ETHERNET 0
#define LWIP_IPV4     1
#define LWIP_ICMP     1
#define LWIP_IGMP     0
#define LWIP_RAW      0
#define LWIP_UDP      1
#define LWIP_UDPLITE  0
#define LWIP_TCP      1
#define LWIP_IPV6     1
#define LWIP_ICMP6    1
#define LWIP_IPV6_MLD 0
#define LWIP_STATS    0
#define LWIP_TIMERS   0

/* Use Glibc malloc()/free() */
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1

#define MEM_ALIGNMENT __SIZEOF_POINTER__

/* netif */
#define LWIP_SINGLE_NETIF   1
#define LWIP_MULTICAST_PING 1

/* IPv4 */
#define IP_FORWARD 0

/* IPv6 */
#define LWIP_IPV6_FORWARD             0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_AUTOCONFIG          0
#define IPV6_FRAG_COPYHEADER          1

/* TCP tuning */
#define TCP_MSS          64000
#define TCP_WND          128000
#define TCP_SND_BUF      128000
#define TCP_SND_QUEUELEN 32
#define LWIP_WND_SCALE   1
#define TCP_RCV_SCALE    1

#ifdef NDEBUG
#define LWIP_DEBUG 0
#else
#define LWIP_DEBUG 1
#endif

/* Debug mode */
#if LWIP_DEBUG
#define IP_DEBUG         LWIP_DBG_OFF
#define IP6_DEBUG        LWIP_DBG_OFF
#define ICMP_DEBUG       LWIP_DBG_OFF
#define TCP_DEBUG        LWIP_DBG_OFF
#define UDP_DEBUG        LWIP_DBG_OFF
#define NETIF_DEBUG      LWIP_DBG_OFF
#define TIMERS_DEBUG     LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#endif

#define SYS_ARCH_DECL_PROTECT(lev) (void)0
#define SYS_ARCH_PROTECT(lev)      (void)0
#define SYS_ARCH_UNPROTECT(lev)    (void)0

#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define lwip_htons(x)                  htobe16(x)
#define lwip_htonl(x)                  htobe32(x)
#define lwip_strnstr(buffer, token, n) strnstr(buffer, token, n)
#define lwip_stricmp(str1, str2)       stricmp(str1, str2)
#define lwip_strnicmp(str1, str2, len) strnicmp(str1, str2, len)
#define lwip_itoa(result, bufsize, number) \
    snprintf(result, bufsize, "%d", number)

#define NSPROXY_MODIFIED 1

#define NSPROXY_LOCAL_IP   "172.23.255.255"
#define NSPROXY_GATEWAY_IP "172.23.255.254"
#define NSPROXY_NETMASK    "255.255.255.254"
#define NSPROXY_MTU        65000

#define NSPROXY_TCP_IDLE_TIMEOUT 7203

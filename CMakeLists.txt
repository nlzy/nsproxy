cmake_minimum_required(VERSION 3.0)

project(nsproxy C)

set(CMAKE_C_STANDARD 90)

add_executable(nsproxy
    lwip/inet_chksum.c
    lwip/init.c
    lwip/ip.c
    lwip/ipv4/icmp.c
    lwip/ipv4/ip4_addr.c
    lwip/ipv4/ip4.c
    lwip/ipv4/ip4_frag.c
    lwip/ipv6/icmp6.c
    lwip/ipv6/inet6.c
    lwip/ipv6/ip6_addr.c
    lwip/ipv6/ip6.c
    lwip/ipv6/ip6_frag.c
    lwip/ipv6/nd6.c
    lwip/netif.c
    lwip/pbuf.c
    lwip/tcp.c
    lwip/tcp_in.c
    lwip/tcp_out.c
    lwip/udp.c
    src/main.c
    src/core.c
    src/loop.c
    src/direct.c
    src/socks.c
    src/http.c
    src/dns.c
)

target_include_directories(nsproxy PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/lwip/include"
    "${CMAKE_CURRENT_LIST_DIR}/src"
)

target_compile_definitions(nsproxy PRIVATE
    _GNU_SOURCE
    _FORTIFY_SOURCE=2
)

target_compile_options(nsproxy PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-array-bounds # caused by tricky hacks in lwIP
    -fstack-protector-strong
    $<$<CONFIG:Debug>:-fsanitize=address>
)

target_link_options(nsproxy PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address>
)

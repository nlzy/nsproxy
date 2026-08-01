cmake_minimum_required(VERSION 3.10)

project(nsproxy VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON)

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
    src/core.c
    src/csignal.c
    src/direct.c
    src/http.c
    src/loop.c
    src/main.c
    src/skutils.c
    src/socks.c
    src/tcpdns.c
)

target_include_directories(nsproxy PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/lwip/include"
    "${CMAKE_CURRENT_LIST_DIR}/src"
)

target_compile_definitions(nsproxy PRIVATE
    _GNU_SOURCE
    _FORTIFY_SOURCE=3
    NSPROXY_VERSION=${PROJECT_VERSION}
)

target_compile_options(nsproxy PRIVATE
    -fstack-protector-strong
    -Wall
    -Wextra
    -Wpedantic
    -Wvla
    -Wno-unused-parameter # annoying in callback style programing
    -Wno-array-bounds     # caused by tricky hacks in lwIP
    $<$<C_COMPILER_ID:Clang>:-Wno-gnu-zero-variadic-macro-arguments> # suppress clang warning GNU extension ##__VA_ARGS__
)

target_link_options(nsproxy PRIVATE
    -Wl,-z,now
)

include(GNUInstallDirs)

install(TARGETS nsproxy
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES nsproxy.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

install(FILES COPYING README
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

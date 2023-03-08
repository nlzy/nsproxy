cmake_minimum_required(VERSION 3.10)

project(nsproxy C)

set(CMAKE_C_STANDARD 90)

set(CMAKE_C_FLAGS      "${CMAKE_C_FLAGS}      -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

set(CMAKE_C_FLAGS_DEBUG      "${CMAKE_C_FLAGS_DEBUG}      -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")

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
    main.c
    hook.c
    loop.c
    direct.c
    socks.c
    fakedns.c
)

target_include_directories(nsproxy PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/lwip/include
    ${CMAKE_CURRENT_LIST_DIR}
)

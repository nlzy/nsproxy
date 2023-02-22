cmake_minimum_required(VERSION 3.10)

project(nwrap C)

set(CMAKE_C_STANDARD 90)

add_executable(tun2sock-lwip
    inet_chksum.c
    init.c
    ip.c
    ipv4/icmp.c
    ipv4/ip4_addr.c
    ipv4/ip4.c
    ipv4/ip4_frag.c
    ipv6/icmp6.c
    ipv6/inet6.c
    ipv6/ip6_addr.c
    ipv6/ip6.c
    ipv6/ip6_frag.c
    ipv6/nd6.c
    main.c
    mem.c
    memp.c
    netif.c
    pbuf.c
    tcp.c
    tcp_in.c
    tcp_out.c
    timeouts.c
    udp.c
)

target_include_directories(tun2sock-lwip PUBLIC ./include)

set(CMAKE_C_FLAGS      "${CMAKE_C_FLAGS}      -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

set(CMAKE_C_FLAGS_DEBUG      "${CMAKE_C_FLAGS_DEBUG}      -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")
set(CMAKE_C_FLAGS_RELWITHDEBINFO      "${CMAKE_C_FLAGS_RELWITHDEBINFO}      -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_LINKER_FLAGS_RELWITHDEBINFO} -fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined")

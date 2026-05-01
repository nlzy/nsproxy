#pragma once
#include <stddef.h>
#include <sys/socket.h>
#include "loop.h"

struct sk_comm {
    struct epcb_ops epcb;

    struct loopctx *loop;

    int sfd;
    int stype;
    unsigned int events;

    size_t nsent;
    size_t nread;

    char desc[64];
};

int skcomm_common_connect(struct sk_comm *comm, const char *addr,
                          uint16_t port);

int skcomm_common_evctl(struct sk_comm *comm, unsigned int event, int enable);
ssize_t skcomm_common_send(struct sk_comm *comm, const char *data, size_t size);
ssize_t skcomm_common_sendmsg(struct sk_comm *comm, struct msghdr *msg);
ssize_t skcomm_common_recv(struct sk_comm *comm, char *data, size_t size);

int skcomm_common_shutdown(struct sk_comm *priv, int how, int rst);
void skcomm_common_close(struct sk_comm *comm);

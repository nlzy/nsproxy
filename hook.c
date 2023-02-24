#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "direct.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

/* UDP */
static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    char buffer[65535];
    struct pbuf *ptr;

    if (p->len == p->tot_len) {
        pcb->conn->send(pcb->conn, p->payload, p->tot_len);
    } else {
        pbuf_copy_partial(p, buffer, p->tot_len, 0);
        pcb->conn->send(pcb->conn, buffer, p->tot_len);
    }

    pbuf_free(p);
}

void udp_handle_event(void *userp, int event)
{
    struct udp_pcb *pcb = userp;
    char buffer[65535];
    ssize_t nread;
    struct pbuf *p;

    if (event & EPOLLIN) {
        nread = pcb->conn->recv(pcb->conn, buffer, sizeof(buffer));
        if (nread > 0) {
            if ((p = pbuf_alloc_reference(buffer, nread, PBUF_REF)) == NULL) {
                fprintf(stderr, "Out of Memory.\n");
                abort();
            }
            udp_send(pcb, p);
            pbuf_free(p);
        }
    }

    if (event & EPOLLOUT) {
        pcb->conn->send(pcb->conn, NULL, 0);
    }

    if (event & (EPOLLERR | EPOLLHUP)) {
        /* no op, timer will release this pcb */
        return;
    }
}

void hook_on_udp_new(struct udp_pcb *pcb)
{
    pcb->recv = &udp_recv_cb;
    direct_udp_create(&pcb->conn, netif_default->state, pcb, &udp_handle_event);
    pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

/* TCP */

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                         err_t err);

void tcp_handle_event(void *userp, int type)
{
    struct tcp_pcb *pcb = userp;
    struct sk_ops *conn = pcb->conn;
    char buffer[CONFIG_MTU];
    ssize_t nread, nsent;
    size_t i;

    if (type & EPOLLERR) {
        tcp_abort(pcb);
        return;
    }

    if (type & EPOLLIN) {
        if (TCP_SND_QUEUELEN == tcp_sndqueuelen(pcb)) {
            nread = conn->recv(conn, buffer, 0);
        } else {
            nread = conn->recv(conn, buffer, sizeof(buffer));
        }

        if (nread > 0) {
            tcp_write(pcb, buffer, nread, TCP_WRITE_FLAG_COPY);
            tcp_output(pcb);
        } else if (nread == 0) {
            tcp_shutdown(pcb, 0, 1);
        } else {
            /* ERR, will handle in EPOLLERR, just continue*/
        }
    }

    if (type & EPOLLOUT) {
        for (i = 0; i < pcb->nrecvq; i++) {
            nsent = conn->send(conn, pcb->rcvq[i]->payload, pcb->rcvq[i]->len);
            if (nsent != pcb->rcvq[i]->len)
                abort();
            tcp_recved(pcb, pcb->rcvq[i]->len);
            pbuf_free(pcb->rcvq[i]);
        }
        pcb->nrecvq = 0;
        conn->send(conn, NULL, 0);
    }

    if (type & EPOLLHUP) {
        conn->destroy(conn);
        pcb->conn = NULL;
        tcp_shutdown(pcb, 1, 1);
        tcp_close(pcb);
    }
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    if (tcp_sndqueuelen(pcb) == 0) {
        tcp_handle_event(pcb, EPOLLIN);
    }
    return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                         err_t err)
{
    struct sk_ops *conn = pcb->conn;
    ssize_t nsent;

    if (!conn) {
        tcp_abort(pcb);
        if (p)
            pbuf_free(p);
        return ERR_ABRT;
    }

    if (!p) {
        conn->shutdown(conn, SHUT_WR);
        return ERR_OK;
    }

    /* ACK immediatly */
    pcb->flags |= TF_ACK_NOW;
    tcp_output(pcb);

    if (p->len != p->tot_len)
        abort();

    nsent = conn->send(conn, p->payload, p->len);

    if (nsent == p->len) {
        tcp_recved(pcb, nsent);
        pbuf_free(p);
        return ERR_OK;
    } else if (nsent == -EAGAIN) {
        pcb->rcvq[pcb->nrecvq++] = p;
        return ERR_OK;
    }

    return ERR_OK;
}

void hook_on_tcp_new(struct tcp_pcb *pcb)
{
    tcp_nagle_disable(pcb);

    tcp_sent(pcb, &tcp_sent_cb);
    tcp_recv(pcb, &tcp_recv_cb);

    direct_tcp_create(&pcb->conn, netif_default->state, pcb, &tcp_handle_event);
    pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

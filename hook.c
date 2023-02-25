#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "direct.h"
#include "socks.h"
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
    socks_udp_create(&pcb->conn, netif_default->state, pcb, &udp_handle_event);
    pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

/* TCP */

void tcp_handle_event(void *userp, int type)
{
    struct tcp_pcb *pcb = userp;
    struct sk_ops *conn = pcb->conn;
    ssize_t nread, nsent;
    char buffer[TCP_SND_BUF];

    if (type & EPOLLERR) {
        conn->destroy(conn);
        pcb->conn = NULL;
        tcp_abort(pcb);
        return;
    }

    if (type & EPOLLIN) {
        nread = tcp_sndqueuelen(pcb) == TCP_SND_QUEUELEN
                    ? 0
                    : LWIP_MIN(sizeof(buffer), tcp_sndbuf(pcb));
        nread = conn->recv(conn, buffer, nread);
        if (nread > 0) {
            if (tcp_write(pcb, buffer, nread, TCP_WRITE_FLAG_COPY) != ERR_OK) {
                fprintf(stderr, "Out of Memory.\n");
                abort();
            }
            tcp_output(pcb);
        } else if (nread == 0) {
            tcp_shutdown(pcb, 0, 1);
        } else {
            /* ERR, will handle in EPOLLERR, just continue*/
        }
    }

    if (type & EPOLLOUT) {
        nsent = conn->send(conn, pcb->rcvq, pcb->nrcvq);
        if (nsent > 0) {
            pcb->nrcvq -= nsent;
            memmove(pcb->rcvq, pcb->rcvq + nsent, pcb->nrcvq);
            tcp_recved(pcb, nsent);
        } else {
            /* ERR, will handle in EPOLLERR, just continue*/
        }
    }

    if (type & EPOLLHUP) {
        conn->destroy(conn);
        pcb->conn = NULL;
        tcp_close(pcb);
    }
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    if (TCP_SND_BUF == pcb->snd_buf)
        tcp_handle_event(pcb, EPOLLIN);
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

    pbuf_copy_partial(p, pcb->rcvq + pcb->nrcvq, p->tot_len, 0);
    pcb->nrcvq += p->tot_len;
    pbuf_free(p);

    tcp_handle_event(pcb, EPOLLOUT);
    return ERR_OK;
}

void hook_on_tcp_new(struct tcp_pcb *pcb)
{
    tcp_nagle_disable(pcb);

    tcp_sent(pcb, &tcp_sent_cb);
    tcp_recv(pcb, &tcp_recv_cb);

    socks_tcp_create(&pcb->conn, netif_default->state, pcb, &tcp_handle_event);
    pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

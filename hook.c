#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#include "direct.h"
#include "fakedns.h"
#include "http.h"
#include "socks.h"

/* UDP */

void udp_handle_event(void *userp, unsigned int event)
{
    struct udp_pcb *pcb = userp;
    struct sk_ops *conn = pcb->conn;
    char buffer[65535];
    ssize_t nread, nsent;
    struct pbuf *p;
    size_t i;

    if (event & (EPOLLERR | EPOLLHUP)) {
        conn->destroy(conn);
        pcb->conn = NULL;
        udp_remove(pcb);
        return;
    }

    if (event & EPOLLIN) {
        nread = conn->recv(conn, buffer, sizeof(buffer));
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
        for (i = 0; i < pcb->nrcvq; i++) {
            p = pcb->rcvq[i];
            if (p->len == p->tot_len) {
                nsent = pcb->conn->send(pcb->conn, p->payload, p->tot_len);
            } else {
                pbuf_copy_partial(p, buffer, p->tot_len, 0);
                nsent = pcb->conn->send(pcb->conn, buffer, p->tot_len);
            }
            if (nsent > 0) {
                pbuf_free(p);
                continue;
            } else {
                break;
            }
        }
        pcb->nrcvq -= i;
        if (pcb->nrcvq == 0) {
            conn->evctl(conn, EPOLLOUT, 0);
        } else {
            memmove(pcb->rcvq, pcb->rcvq + i,
                    pcb->nrcvq * sizeof(pcb->rcvq[0]));
            conn->evctl(conn, EPOLLOUT, 1);
        }
    }
}

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                        const ip_addr_t *addr, u16_t port)
{
    struct sk_ops *conn = pcb->conn;
    ssize_t nsent;

    if (!conn || !p) {
        udp_remove(pcb);
        if (p)
            pbuf_free(p);
        return;
    }

    if (pcb->nrcvq == arraysizeof(pcb->rcvq)) {
        memmove(pcb->rcvq, pcb->rcvq + 1,
                (arraysizeof(pcb->rcvq) - 1) * sizeof(pcb->rcvq[0]));
        pcb->rcvq[arraysizeof(pcb->rcvq) - 1] = p;
    } else {
        pcb->rcvq[pcb->nrcvq] = p;
        pcb->nrcvq++;
    }

    udp_handle_event(pcb, EPOLLOUT);
}

void hook_on_udp_new(struct udp_pcb *pcb)
{
    pcb->recv = &udp_recv_cb;

    /* TODO: make configurable */
    if (pcb->local_port == 53) {
        tcpdns_create(&pcb->conn, ip_current_netif()->state,
                         &udp_handle_event, pcb);
        pcb->conn->connect(pcb->conn, CONFIG_HIJACK_DNS, pcb->local_port);
    } else {
        socks_udp_create(&pcb->conn, ip_current_netif()->state,
                         &udp_handle_event, pcb);
        pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip),
                           pcb->local_port);
    }
}

/* TCP */

void tcp_handle_event(void *userp, unsigned int event)
{
    struct tcp_pcb *pcb = userp;
    struct sk_ops *conn = pcb->conn;
    ssize_t nread, nsent;
    char buffer[TCP_SND_BUF];

    if (event & EPOLLERR) {
        conn->destroy(conn);
        pcb->conn = NULL;
        tcp_abort(pcb);
        return;
    }

    if (event & EPOLLIN) {
        if (!tcp_sndbuf(pcb) || tcp_sndqueuelen(pcb) > TCP_SND_QUEUELEN - 4) {
            nread = -1;
        } else {
            nread = conn->recv(conn, buffer,
                               LWIP_MIN(tcp_mss(pcb), tcp_sndbuf(pcb)));
        }
        if (nread > 0) {
            if (tcp_write(pcb, buffer, nread, TCP_WRITE_FLAG_COPY) != ERR_OK) {
                fprintf(stderr, "Out of Memory.\n");
                abort();
            }
            tcp_output(pcb);
        } else if (nread == 0) {
            tcp_shutdown(pcb, 0, 1);
            conn->evctl(conn, EPOLLIN, 0);
        } else if (nread == -EAGAIN) {
            conn->evctl(conn, EPOLLIN, 1);
        } else {
            conn->evctl(conn, EPOLLIN, 0);
        }
    }

    if (event & EPOLLOUT) {
        if (pcb->nrcvq == 0) {
            nsent = -1;
        } else {
            nsent = conn->send(conn, pcb->rcvq, pcb->nrcvq);
        }
        if (nsent > 0) {
            pcb->nrcvq -= nsent;
            memmove(pcb->rcvq, pcb->rcvq + nsent, pcb->nrcvq);
            tcp_recved(pcb, nsent);
        } else if (nsent == -EAGAIN) {
            conn->evctl(conn, EPOLLOUT, 1);
        } else {
            conn->evctl(conn, EPOLLOUT, 0);
        }
    }

    if (event & EPOLLHUP) {
        conn->destroy(conn);
        pcb->conn = NULL;
        tcp_close(pcb);
    }
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct sk_ops *conn = pcb->conn;

    if ((pcb->state == ESTABLISHED || pcb->state == CLOSE_WAIT) &&
        tcp_sndbuf(pcb) > TCP_SNDLOWAT)
        conn->evctl(conn, EPOLLIN, 1);

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

    tcp_ack(pcb);

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

    http_tcp_create(&pcb->conn, ip_current_netif()->state, &tcp_handle_event,
                     pcb);
    pcb->conn->connect(pcb->conn, ipaddr_ntoa(&pcb->local_ip), pcb->local_port);
}

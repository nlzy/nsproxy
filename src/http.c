/*
 * Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "http.h"

#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "loop.h"
#include "proxy.h"
#include "skutils.h"

#define HTTP_HS_BUFF 4096

enum {
    PHASE_FAILED = 0,
    PHASE_SEND_REQUEST,
    PHASE_RECV_REPLY,
    PHASE_FORWARDING
};

static const char *phasestr[] = {
    [PHASE_SEND_REQUEST] = "send-request",
    [PHASE_RECV_REPLY] = "recv-reply",
    [PHASE_FORWARDING] = "forwarding",
};

/* Base64 output length (include NUL terminate) */
#define BASE64_OUTLEN(inlen) (((inlen) + 2) / 3 * 4 + 1)

/* Base64 encoding table */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 encode function
   Returns the number of bytes written to output (include NUL terminate)
*/
static size_t base64_encode(char *output, size_t outlen, const void *binary,
                            size_t inlen)
{
    size_t i, j;

    if (inlen > (SIZE_MAX - 1) / 4 * 3 || outlen < ((inlen + 2) / 3) * 4 + 1)
        return 0;

    for (i = 0, j = 0; i < inlen;) {
        unsigned char a3[3] = { 0 };
        unsigned char a4[4];
        size_t k;

        for (k = 0; k < 3 && i < inlen; k++)
            a3[k] = ((unsigned char *)binary)[i++];

        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) | (a3[1] >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) | (a3[2] >> 6);
        a4[3] = a3[2] & 0x3f;

        output[j++] = base64_chars[a4[0]];
        output[j++] = base64_chars[a4[1]];
        output[j++] = k > 1 ? base64_chars[a4[2]] : '=';
        output[j++] = k > 2 ? base64_chars[a4[3]] : '=';
    }

    output[j++] = '\0';
    return j;
}

struct proxy_http {
    struct proxy ops;

    /* loop */
    struct loopctx *loop;
    struct epcb_ops epcb;

    /* socket */
    int sfd;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;

    /* target */
    char ip[IP_MAXLEN + 1];
    uint16_t port;

    /* info */
    struct skinfo info;

    /* handshake */
    int phase;
    struct buff *hsbuff;
};

static void http_handshake_perror(struct proxy_http *self, int err)
{
    if (err > 0)
        loglv0("Proxy server reset unexpectedly during HTTP handshake phase "
               "[%s]: %s", phasestr[self->phase], strerror(err));
    else
        loglv0("Proxy server closed unexpectedly during HTTP handshake phase "
               "[%s]", phasestr[self->phase]);
}

/* epoll event callback
   used of receiving http response */
static void http_handshake_input(struct proxy_http *self)
{
    struct buff *buff = self->hsbuff;
    ssize_t nread;
    char *crlf2;
    ssize_t ndiscard;
    char vermin;
    int code;

    /* Use MSG_PEEK here, if some application layer data has been returned,
       we can carefuly not to touch them
       Treat buff->data as string, never forget set a '\0' after recv()
    */
    nread = recv(self->sfd, buff->data + buff->size,
                 buff->capacity - buff->size - 1, MSG_PEEK);
    if (nread == -1 && errno == EAGAIN) {
        return;
    } else if (nread <= 0) {
        http_handshake_perror(self, nread == -1 ? errno : 0);
        goto failed_handshake;
    }

    (buff->data + buff->size)[nread] = '\0';

    /* serch from start every time, servers (who?) may trim \r\n\r\n */
    crlf2 = strstr(buff->data, "\r\n\r\n");

    /* number of bytes need to discard after recv(..., MSG_PEEK) */
    ndiscard = crlf2 ? (crlf2 + strlen("\r\n\r\n") - (buff->data + buff->size))
                     : nread;

    /* discard http response part in socket buffer */
    nread = recv(self->sfd, buff->data + buff->size, ndiscard, 0);
    if (nread != ndiscard) {
        loglv0("Handshake failed, recv() returned %zd, expected %zd", nread,
               ndiscard);
        goto failed_handshake;
    }
    buff->size += ndiscard;

    /* handshake not finished */
    if (!crlf2) {
        /* failed, handshake not finished but buffer full */
        if (buff->size == buff->capacity - 1) {
            loglv0("Proxy server returned a header that is too large during the"
                   " handshake.");
            goto failed_handshake;
        }
        /* if not failed, wait for rest handshake message */
        return;
    }

    /* check response */
    if (sscanf(buff->data, "HTTP/1.%c %d", &vermin, &code) != 2) {
        loglv0("Proxy server returned invalid HTTP response header during the "
               "handshake.");
        goto failed_handshake;
    }
    if (code != 200) {
        if (code == 407 || code == 401) {
            loglv0("Proxy authentication failed (HTTP %d). Please check your "
                   "username and password.", code);
        } else {
            loglv0("Proxy server returned HTTP error %d", code);
        }
        goto failed_handshake;
    }

    self->phase = PHASE_FORWARDING;
    loglv2("... handshaked %s:%u/tcp", self->ip, (unsigned)self->port);

    /* good, handshake finish, listen and forward epoll event for user */
    skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                  EPOLLOUT | EPOLLIN, EVUPD);

    free(self->hsbuff);
    self->hsbuff = NULL;
    return;

failed_handshake:
    self->phase = PHASE_FAILED;
    self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
}

/* epoll event callback
   used of sending http request */
static void http_handshake_output(struct proxy_http *self)
{
    struct buff *buff = self->hsbuff;
    ssize_t nsent;

    /* it's first called to this function, assembly request */
    if (!buff->size) {
        const char *lb, *rb;

        if (strchr(self->ip, ':') != NULL) {
            /* addr is IPv6 */
            lb = "[";
            rb = "]";
        } else {
            lb = rb = "";
        }

        if (strlen(current_nspconf()->proxyuser)) {
            char credentials[AUTH_MAXLEN * 2 + 1 + 1];
            char base64[BASE64_OUTLEN(AUTH_MAXLEN * 2 + 1)];

            snprintf(credentials, sizeof(credentials), "%s:%s",
                     current_nspconf()->proxyuser, current_nspconf()->proxypass);
            base64_encode(base64, sizeof(base64), credentials, 
                          strlen(credentials));

            buff->size = snprintf(buff->data, buff->capacity,
                "CONNECT %s%s%s:%u HTTP/1.1"       "\r\n"
                "Host: %s%s%s:%u"                  "\r\n"
                "Proxy-Authorization: Basic %s"    "\r\n"
                "\r\n",
                lb, self->ip, rb, (unsigned)self->port,
                lb, self->ip, rb, (unsigned)self->port,
                base64);
        } else {
            buff->size = snprintf(buff->data, buff->capacity,
                "CONNECT %s%s%s:%u HTTP/1.1"    "\r\n"
                "Host: %s%s%s:%u"               "\r\n"
                "\r\n",
                lb, self->ip, rb, (unsigned)self->port,
                lb, self->ip, rb, (unsigned)self->port);
        }
    }

    nsent = send(self->sfd, buff->data, buff->size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno != EAGAIN) {
            http_handshake_perror(self, errno);
            self->phase = PHASE_FAILED;
            self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
        }
        return;
    }
    buff->size -= nsent;

    if (buff->size != 0) {
        /* partial write, wait next time to write rest */
        memmove(buff->data, buff->data + nsent, buff->size);
        return;
    }

    /* good, http request has been send */
    self->phase = PHASE_RECV_REPLY;
    skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb, EPOLLIN,
                  EVUPD);
}

static void http_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct proxy_http *self = container_of(epcb, struct proxy_http, epcb);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events);
        return;
    } else if (self->phase == PHASE_FAILED) {
        self->userev(self->userp, EPOLLIN | EPOLLOUT | EPOLLERR);
        return;
    }

    loginfo("http_epcb_events: handshake for %s:%u/tcp %s", self->ip,
            (unsigned)self->port, phasestr[self->phase]);

    if (self->phase == PHASE_SEND_REQUEST) {
        http_handshake_output(self);
    } else {
        http_handshake_input(self);
    }
}

/* impl for struct proxy :: shutdown */
static int http_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return self->phase != PHASE_FORWARDING
               ? -EAGAIN
               : skutils_shutdown(&self->info, self->loop, &self->sfd, how,
                                  rst);
}

/* impl for struct proxy :: evctl */
static int http_evctl(struct proxy *proxy, unsigned int event, int mode)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    return self->phase != PHASE_FORWARDING
               ? -EAGAIN
               : skutils_evctl(self->loop, self->sfd, &self->events,
                               &self->epcb, event, mode);
}

/* impl for struct proxy :: send */
static ssize_t http_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);

    if (self->phase == PHASE_FAILED)
        return -ECONNABORTED; /* handshake failed */
    else if (self->phase != PHASE_FORWARDING)
        return -EINPROGRESS; /* handshake is not finished */

    return skutils_send(&self->info, self->sfd, data, size);
}

/* impl for struct proxy :: recv */
static ssize_t http_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);

    if (self->phase == PHASE_FAILED)
        return -ECONNABORTED; /* handshake failed */
    else if (self->phase != PHASE_FORWARDING)
        return -EINPROGRESS; /* handshake is not finished */

    return skutils_recv(&self->info, self->sfd, data, size);
}

/* impl for struct proxy :: get */
static void http_get(struct proxy *proxy)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    self->refcnt++;
}

/* impl for struct proxy :: put */
static void http_put(struct proxy *proxy)
{
    struct proxy_http *self = container_of(proxy, struct proxy_http, ops);
    if (--self->refcnt == 0) {
        skutils_close_unreg(&self->info, self->loop, &self->sfd);
        free(self->hsbuff);
        free(self);
    }
}

/* global vtable of proxy_http */
static const struct proxy_ops http_ops = {
    .shutdown = &http_shutdown,
    .evctl = &http_evctl,
    .send = &http_send,
    .recv = &http_recv,
    .get = &http_get,
    .put = &http_put,
};

/* create a tcp connection
   this connection is proxied via http proxy server */
struct proxy *http_tcp_create(struct loopctx *loop, userev_fn_t *userev,
                              void *userp, const char *ip, uint16_t port)
{
    struct proxy_http *self;
    struct nspconf *conf = current_nspconf();

    loginfo("http_tcp_create: creating new struct proxy_http for %s:%u/tcp",
            ip, (unsigned)port);

    if (strlen(ip) > IP_MAXLEN)
        return NULL;

    if ((self = calloc(1, sizeof(struct proxy_http))) == NULL)
        oom();
    if ((self->hsbuff = buff_calloc(HTTP_HS_BUFF)) == NULL)
        oom();

    /* init */
    self->ops.ops = &http_ops;
    self->loop = loop;
    self->epcb.on_epoll_events = &http_epcb_events;
    self->sfd = -1;
    self->events = 0;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;
    strcpy(self->ip, ip);
    self->port = port;
    self->info.proto = "tcp";
    self->info.addr = self->ip;
    self->info.port = self->port;

    /* perform connect */
    self->sfd = skutils_connect(&self->info, conf->proxysrv, conf->proxyport,
                                SOCK_STREAM);
    if (self->sfd < 0) {
        free(self->hsbuff);
        free(self);
        return NULL;
    }

    /* good, start handshake */
    self->phase = PHASE_SEND_REQUEST;
    skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb, EPOLLOUT,
                  EVUPD);

    return &self->ops;
}

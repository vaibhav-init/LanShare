/* http.c — request parsing + routing. Three routes total:
 *   GET  /        → the upload page
 *   POST /upload  → PIN-gated multipart save (fs.c)
 *   anything else → 404/405
 * Trust boundary: everything after the request line is untrusted input.
 */
#define _GNU_SOURCE  /* strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "page.h"
#include "share.h"

#define HDR_CAP MAX_HEADER

/* value of `name` header from a raw header block, or NULL */
static const char *hdr_val(const char *hdrs, const char *name,
                           char *out, size_t n)
{
    size_t nl = strlen(name);
    const char *p = hdrs;
    while ((p = strstr(p, name)) != NULL) {
        const char *after = p + nl;
        if ((p == hdrs || p[-1] == '\n') &&
            (*after == ':' || (*after == ' ' && after[1] == ':'))) {
            if (*after == ' ') after++;                 /* "Name :" form */
            after++;                                    /* skip ':' */
            while (*after == ' ' || *after == '\t') after++;
            size_t i = 0;
            while (after[i] && after[i] != '\r' && after[i] != '\n' && i < n - 1) {
                out[i] = after[i]; i++;
            }
            out[i] = 0;
            return out;
        }
        p = after;
    }
    return NULL;
}

static int send_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static void reply(int fd, const char *code, const char *ctype,
                  const char *body, size_t n)
{
    char head[256];
    int h = snprintf(head, sizeof head,
                     "HTTP/1.1 %s\r\nContent-Type: %s\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     code, ctype, n);
    if (send_all(fd, head, (size_t)h) == 0) send_all(fd, body, n);
}

static void reply_json(int fd, const char *code, const char *json)
{
    reply(fd, code, "application/json", json, strlen(json));
}

/* %XX decode in place (path form: '+' stays '+') */
static void url_decode(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            int v;
            if (sscanf(r + 1, "%2x", &v) == 1) { *w++ = (char)v; r += 2; }
            else *w++ = *r;
        } else *w++ = *r;
    }
    *w = 0;
}

/* read up to \r\n\r\n; returns total bytes including the CRLFCRLF, -1 on error.
   Everything after the header block stays in buf (start of the body). */
static int read_headers(int fd, char *buf, size_t cap)
{
    size_t got = 0;
    while (got < cap - 1) {
        ssize_t r = read(fd, buf + got, cap - 1 - got);
        if (r <= 0) return -1;
        got += (size_t)r;
        buf[got] = 0;
        char *end = strstr(buf, "\r\n\r\n");
        if (end) return (int)((end - buf) + 4);
    }
    return -1;
}

void http_serve(int conn, const Config *cfg)
{
    char buf[MAX_HEADER];
    int hlen = read_headers(conn, buf, sizeof buf);
    if (hlen < 0) return;
    buf[hlen - 4] = 0;                                    /* terminate header block */

    char method[8] = "", path[1024] = "";
    if (sscanf(buf, "%7s %1023s HTTP/1.%*d", method, path) != 2) return;
    url_decode(path);

    char client[64];
    net_client_ip(conn, client, sizeof client);

    char vpin[32] = "", vtype[256] = "", vlen[32] = "";
    hdr_val(buf, "X-Pair", vpin, sizeof vpin);
    hdr_val(buf, "Content-Type", vtype, sizeof vtype);
    hdr_val(buf, "Content-Length", vlen, sizeof vlen);

    if (!strcmp(method, "GET") && (!strcmp(path, "/") || !strncmp(path, "/?", 2))) {
        printf("[lanshare] GET  /  from %s\n", client);
        reply(conn, "200 OK", "text/html; charset=utf-8",
              PAGE, sizeof PAGE - 1);
        return;
    }

    if (!strcmp(method, "POST") && !strncmp(path, "/upload", 7)) {
        if (!fs_pin_ok(cfg, vpin)) {
            printf("[lanshare] POST /upload  DENIED (pin) from %s\n", client);
            reply_json(conn, "403 Forbidden",
                       "{\"ok\":false,\"error\":\"pin\"}");
            return;
        }
        unsigned long clen = vlen[0] ? strtoul(vlen, NULL, 10) : 0;
        if (clen == 0 || clen > MAX_BODY) {
            reply_json(conn, "413 Payload Too Large",
                       "{\"ok\":false,\"error\":\"size\"}");
            return;
        }
        /* boundary= from Content-Type (strip optional quotes) */
        char *b = strcasestr(vtype, "boundary=");
        if (!b) {
            reply_json(conn, "400 Bad Request", "{\"ok\":false,\"error\":\"type\"}");
            return;
        }
        b += strlen("boundary=");
        if (*b == '"') { char *q = strchr(b + 1, '"'); if (q) *q = 0; b++; }
        else { char *sc = strchr(b, ';'); if (sc) *sc = 0; }

        char saved[256];
        int n = fs_save_multipart(conn, cfg, b, clen,
                                  buf + hlen, strlen(buf + hlen),
                                  saved, sizeof saved);
        if (n > 0) {
            printf("[lanshare] POST /upload  saved %s from %s\n", saved, client);
            char js[320];
            snprintf(js, sizeof js, "{\"ok\":true,\"file\":\"%s\"}", saved);
            reply_json(conn, "200 OK", js);
        } else {
            reply_json(conn, "500 Internal Server Error",
                       "{\"ok\":false,\"error\":\"io\"}");
        }
        return;
    }

    if (!strcmp(method, "GET") || !strcmp(method, "POST")) {
        reply(conn, "404 Not Found", "text/plain", "not here\n", 9);
        return;
    }
    reply(conn, "405 Method Not Allowed", "text/plain", "no\n", 3);
}

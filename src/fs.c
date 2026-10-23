/* fs.c — trust boundary + the streaming multipart parser.
 *
 * Everything a browser sends touches this file first, so the security
 * checks (PIN, filename sanitizing, body caps) live here, next to the
 * parser that enforces them.
 *
 * Upload bodies are STREAMED: a rolling hold-back buffer scans for the
 * multipart boundary across chunk edges, so a 2 GB video never sits in RAM.
 */
#define _GNU_SOURCE  /* memmem */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "share.h"

#define SCAN_BUF  65536
#define HDRS_MAX  4096

static pthread_mutex_t pin_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---- tiny io helpers ------------------------------------------------ */

static int write_all(int fd, const char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* ---- rolling scanner ------------------------------------------------
 * The scanner owns a buffer; `len` bytes are live starting at buf[0].
 * It never lets a potential partial needle escape to the writer: the last
 * needle_len-1 bytes are always held back until a newer chunk resolves them.
 */
typedef struct { int fd; char buf[SCAN_BUF]; size_t len; } Scan;

static int scan_seed(Scan *s, int fd, const char *lead, size_t lead_len)
{
    s->fd = fd;
    if (lead_len > sizeof s->buf) return -1;
    memcpy(s->buf, lead, lead_len);
    s->len = lead_len;
    return 0;
}

/* Writes everything before the next `needle` to `out` (out < 0 discards).
 * On success the needle itself stays at buf[0] for the caller to consume.
 * 1 = found, 0 = clean EOF (needle never came), -1 = io error/timeout. */
static int scan_until(Scan *s, const char *needle, int out)
{
    size_t nlen = strlen(needle);
    if (nlen >= sizeof s->buf) return -1;
    for (;;) {
        char *hit = memmem(s->buf, s->len, needle, nlen);
        if (hit) {
            size_t off = (size_t)(hit - s->buf);
            if (out >= 0 && write_all(out, s->buf, off) < 0) return -1;
            s->len -= off;
            memmove(s->buf, hit, s->len);
            return 1;
        }
        size_t keep = nlen ? nlen - 1 : 0;
        if (s->len > keep) {
            size_t drop = s->len - keep;
            if (out >= 0 && write_all(out, s->buf, drop) < 0) return -1;
            s->len -= drop;
            memmove(s->buf, s->buf + drop, s->len);
        }
        if (s->len == sizeof s->buf) return -1;  /* cannot happen: keep < cap */
        ssize_t r = read(s->fd, s->buf + s->len, sizeof s->buf - s->len);
        if (r == 0) return 0;
        if (r < 0) return -1;
        s->len += (size_t)r;
    }
}

/* Same scan, but the pre-needle bytes are copied out (used for part headers) */
static int scan_until_copy(Scan *s, const char *needle, char *out, size_t outn)
{
    size_t nlen = strlen(needle);
    size_t got = 0;
    for (;;) {
        char *hit = memmem(s->buf, s->len, needle, nlen);
        if (hit) {
            size_t off = (size_t)(hit - s->buf);
            if (off > outn - 1) return -1;                /* header block too big */
            if (got + off > outn - 1) return -1;
            memcpy(out + got, s->buf, off);
            out[got + off] = 0;
            s->len -= off + nlen;
            memmove(s->buf, hit + nlen, s->len);
            return 1;
        }
        size_t keep = nlen - 1;
        size_t take = s->len > keep ? s->len - keep : 0;
        if (got + take > outn - 1) return -1;
        memcpy(out + got, s->buf, take);
        got += take;
        s->len -= take;
        memmove(s->buf, s->buf + take, s->len);
        ssize_t r = read(s->fd, s->buf + s->len, sizeof s->buf - s->len);
        if (r == 0) return 0;
        if (r < 0) return -1;
        s->len += (size_t)r;
    }
}

static void scan_consume(Scan *s, size_t n)
{
    if (n > s->len) n = s->len;
    s->len -= n;
    memmove(s->buf, s->buf + n, s->len);
}

/* ---- PIN gate -------------------------------------------------------- */

int fs_pin_ok(const Config *cfg, const char *pin)
{
    int ok;
    pthread_mutex_lock(&pin_lock);
    if (!pin || strlen(pin) != 4) {
        if (++cfg->pin->fails >= 5) cfg->pin->lock_until = time(NULL) + 30;
        ok = 0;
    } else if (time(NULL) < cfg->pin->lock_until) {
        ok = 0;                                        /* locked out */
    } else if (strcmp(pin, cfg->pin_str) != 0) {
        if (++cfg->pin->fails >= 5) cfg->pin->lock_until = time(NULL) + 30;
        ok = 0;
    } else {
        cfg->pin->fails = 0;
        ok = 1;
    }
    pthread_mutex_unlock(&pin_lock);
    return ok;
}

/* ---- filename sanitizing + unique save -------------------------------
 * Trust boundary: the filename comes from an untrusted browser. Take the
 * basename, drop anything odd, never trust the client's path.
 */
static void sanitize_name(const char *in, char *out, size_t n)
{
    const char *base = in;
    for (const char *p = in; *p; p++)
        if (*p == '/' || *p == '\\') base = p + 1;
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) base = "upload.bin";
    size_t j = 0;
    for (const char *p = base; *p && j + 1 < n; p++)
        out[j++] = (*p >= 32 && *p < 127 && *p != '"' && *p != '\'') ? *p : '_';
    out[j] = 0;
}

/* test hook: the static sanitizer, reachable from the self-check */
void sanitize_name_public(const char *in, char *out, size_t n)
{
    sanitize_name(in, out, n);
}

static int open_unique(const char *dir, char *name, size_t n)
{
    char path[1024];
    for (int i = 0; i < 10000; i++) {
        if (i == 0) snprintf(path, sizeof path, "%s/%s", dir, name);
        else {
            char stem[256], ext[128] = "";
            snprintf(stem, sizeof stem, "%s", name);
            char *dot = strrchr(stem, '.');
            if (dot && dot != stem) { snprintf(ext, sizeof ext, "%s", dot); *dot = 0; }
            snprintf(name, n, "%.180s-%d%.50s", stem, i, ext);
            snprintf(path, sizeof path, "%s/%s", dir, name);
        }
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) return fd;
        if (errno != EEXIST) return -1;
    }
    return -1;
}

/* ---- multipart streaming ---------------------------------------------
 * Body shape:  --B\r\n hdrs \r\n\r\n DATA \r\n--B\r\n hdrs ... \r\n--B--\r\n
 * Loop: skip to boundary, read part headers (filename), stream DATA to
 * disk up to the next \r\n--B, decide continue vs final.
 */
int fs_save_multipart(int sock, const Config *cfg, const char *boundary,
                      unsigned long clen, const char *lead, size_t lead_len,
                      char *savedname, size_t n)
{
    (void)clen; /* clen only capped the request earlier; scanner hits EOF/boundary anyway */
    char needle0[256], needle1[256];
    snprintf(needle0, sizeof needle0, "--%s", boundary);
    snprintf(needle1, sizeof needle1, "\r\n--%s", boundary);
    size_t n0 = strlen(needle0);

    Scan s;
    if (scan_seed(&s, sock, lead, lead_len) < 0) return -1;

    if (scan_until(&s, needle0, -1) != 1) return -1;  /* skip preamble */
    scan_consume(&s, n0);

    int saved = 0;
    savedname[0] = 0;
    for (;;) {
        /* part headers */
        char hdrs[HDRS_MAX];
        int r = scan_until_copy(&s, "\r\n\r\n", hdrs, sizeof hdrs);
        if (r <= 0) { if (saved) break; return -1; }

        char rawname[256] = "upload.bin";
        const char *fn = strcasestr(hdrs, "filename=\"");
        if (fn) {
            const char *p = fn + strlen("filename=\"");
            size_t i = 0;
            while (*p && *p != '"' && i < sizeof rawname - 1) rawname[i++] = *p++;
            rawname[i] = 0;
        }

        char clean[256];
        sanitize_name(rawname, clean, sizeof clean);

        int outfd = open_unique(cfg->root, clean, sizeof clean);
        if (outfd < 0) return -1;
        snprintf(savedname, n, "%s", clean);

        r = scan_until(&s, needle1, outfd);
        close(outfd);
        if (r != 1) {                      /* EOF mid-file = truncated = bad */
            char path[1024];
            snprintf(path, sizeof path, "%s/%s", cfg->root, clean);
            unlink(path);                  /* never keep partial data */
            return -1;
        }
        scan_consume(&s, strlen(needle1));
        saved++;

        /* after needle1: "--" = final boundary, "\r\n" = another part */
        if (s.len < 2) {
            ssize_t rr = read(s.fd, s.buf + s.len, sizeof s.buf - s.len);
            if (rr <= 0) break;            /* no more = done */
            s.len += (size_t)rr;
        }
        if (s.len >= 2 && !memcmp(s.buf, "--", 2)) break;   /* --B-- : done */
        if (s.len >= 2 && !memcmp(s.buf, "\r\n", 2)) {
            scan_consume(&s, 2);
            continue;                                        /* next part */
        }
        break;                             /* unexpected junk: stop */
    }
    return saved;
}

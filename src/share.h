/* share.h — lanshare: phone → laptop file drop over the browser.
 *
 * Run on the laptop; anyone on the WiFi scans a QR (or opens the URL) and
 * uploads files to the shared folder. A per-session 4-digit PIN gates uploads.
 * --tunnel exposes it on any network via an SSH reverse tunnel.
 */
#ifndef LNS_SHARE_H
#define LNS_SHARE_H

#include <stddef.h>

#define DEFAULT_PORT 8000
#define MAX_HEADER   8192
#define MAX_BODY     (1024UL * 1024 * 1024)  /* 1 GiB backstop, parser streams */
#define PID_FILE     "/tmp/lanshare.pid"
#define QR_PNG       "/tmp/lanshare-qr.png"

typedef struct { int fails; long lock_until; } PinState;

typedef struct {
    const char *root;             /* resolved shared dir                */
    int         port;             /* actual bound port                  */
    PinState   *pin;              /* process-wide, mutex-guarded in fs.c */
    char        pin_str[5];       /* "4271" style                       */
    char        public_url[256];  /* tunnel URL, "" = LAN mode          */
} Config;

/* net.c */
int  net_listen(int port);                       /* <0 = error, else fd */
int  net_lan_ip(char *buf, size_t n);
void net_client_ip(int sock, char *buf, size_t n);

/* http.c */
void http_serve(int conn, const Config *cfg);    /* one full request    */

/* fs.c: 1 = allowed, 0 = denied */
int  fs_pin_ok(const Config *cfg, const char *pin_hdr);
/* stream multipart body from sock → files in cfg->root.
   `lead`/`lead_len` = body bytes already read during header parsing.
   Returns number of files saved, -1 on malformed/failed. */
int  fs_save_multipart(int sock, const Config *cfg,
                       const char *boundary, unsigned long clen,
                       const char *lead, size_t lead_len,
                       char *savedname, size_t n);

#endif

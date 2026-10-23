/* main.c — lanshare entry point.
 *
 *   lanshare [dir]          share dir (default ~/Downloads) on the LAN
 *   lanshare [dir] --tunnel also open a public URL via SSH reverse tunnel
 *
 * Per connection: fork(). PIN + throttle state are shared via a tiny
 * MAP_ANONYMOUS mapping so the forked children agree on lockout.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "share.h"

static Config cfg;
static pid_t  ssh_pid = 0;

/* ---- cleanup ---------------------------------------------------------- */
static void cleanup(void)
{
    unlink(PID_FILE);
    if (ssh_pid > 0) kill(ssh_pid, SIGTERM);
}
static void on_sigint(int sig)
{
    (void)sig;
    cleanup();
    _exit(0);
}

/* ---- 4 digits from the kernel CSPRNG ---------------------------------- */
static void gen_pin(char out[5])
{
    unsigned char rb[4];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, rb, 4) != 4) {          /* urandom never fails here */
        for (int i = 0; i < 4; i++) rb[i] = (unsigned char)rand();
    }
    if (fd >= 0) close(fd);
    for (int i = 0; i < 4; i++) out[i] = (char)('0' + rb[i] % 10);
    out[4] = 0;
}

/* ---- ssh reverse tunnel (any-network mode) -----------------------------
 * shortcut: anonymous localhost.run session — URL rotates each start,
 * free tier only. Upgrade to a VPS relay (DESIGN.md v2) for persistence.
 */
static void start_tunnel(int port)
{
    int fds[2];
    if (pipe(fds) < 0) return;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return; }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        setsid();
        char fwd[64];
        snprintf(fwd, sizeof fwd, "80:localhost:%d", port);
        execlp("ssh", "ssh", "-N", "-T", "-o", "ExitOnForwardFailure=yes",
               "-o", "ServerAliveInterval=30", "-o",
               "StrictHostKeyChecking=no", "-R", fwd, "nokey@localhost.run",
               (char *)NULL);
        _exit(127);
    }
    close(fds[1]);

    /* read the banner until a public URL appears (15 s cap) */
    char line[512];
    struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
    time_t deadline = time(NULL) + 15;
    while (time(NULL) < deadline) {
        if (poll(&pfd, 1, 1000) <= 0) continue;
        int n = (int)read(fds[0], line, sizeof line - 1);
        if (n <= 0) break;
        line[n] = 0;
        char *u = strstr(line, "https://");
        if (u) {
            char *e = strpbrk(u, " \r\n\t");
            if (e) *e = 0;
            snprintf(cfg.public_url, sizeof cfg.public_url, "%s", u);
            size_t ul = strlen(cfg.public_url);
            while (ul && cfg.public_url[ul - 1] == '/')   /* "x.lhr.life/" → "x.lhr.life" */
                cfg.public_url[--ul] = 0;
            break;
        }
    }
    close(fds[0]);
    if (cfg.public_url[0]) ssh_pid = pid;
    else kill(pid, SIGTERM);
}

/* ---- display: banner + QR --------------------------------------------- */
static void show_qr(const char *url)
{
    char cmd[768];
    snprintf(cmd, sizeof cmd, "qrencode -s 6 -o %s '%s' 2>/dev/null",
             QR_PNG, url);
    if (system(cmd) == 0) {
        snprintf(cmd, sizeof cmd, "qrencode -t ANSIUTF8 -s 1 '%s'", url);
        FILE *q = popen(cmd, "r");
        if (q) { char l[512]; while (fgets(l, sizeof l, q)) fputs(l, stdout); pclose(q); }
    }
}

/* ---- main -------------------------------------------------------------- */
int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);        /* dead clients must not kill us */
    setvbuf(stdout, NULL, _IOLBF, 0);  /* banner/logs useful when redirected */
    signal(SIGCHLD, SIG_IGN);        /* auto-reap forked children */
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);      /* waybar toggle uses SIGTERM */

    const char *dir = NULL;
    int want_tunnel = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tunnel")) want_tunnel = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("usage: lanshare [dir] [--tunnel]\n"); return 0;
        } else dir = argv[i];
    }
    if (!dir) {
        const char *home = getenv("HOME");
        static char def[512];
        snprintf(def, sizeof def, "%s/Downloads", home ? home : ".");
        dir = def;
    }
    if (mkdir(dir, 0755) && errno != EEXIST) { perror("mkdir"); return 1; }
    static char resolved[512];
    if (!realpath(dir, resolved)) { perror("realpath"); return 1; }

    cfg.root = resolved;
    cfg.pin  = mmap(NULL, sizeof(PinState), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!cfg.pin) { perror("mmap"); return 1; }
    memset(cfg.pin, 0, sizeof(PinState));
    gen_pin(cfg.pin_str);
    cfg.public_url[0] = 0;

    int lfd = -1;
    for (int p = DEFAULT_PORT; p < DEFAULT_PORT + 10 && lfd < 0; p++) {
        cfg.port = p;
        lfd = net_listen(p);
    }
    if (lfd < 0) { fprintf(stderr, "lanshare: no free port\n"); return 1; }

    if (want_tunnel) start_tunnel(cfg.port);

    /* URL other devices open (PIN embedded so scanning pairs instantly) */
    char base[512], url[640];
    if (cfg.public_url[0]) {
        snprintf(base, sizeof base, "%s", cfg.public_url);
    } else {
        char ip[64] = "127.0.0.1";
        net_lan_ip(ip, sizeof ip);
        snprintf(base, sizeof base, "http://%s:%d", ip, cfg.port);
    }
    snprintf(url, sizeof url, "%s/?pin=%s", base, cfg.pin_str);

    /* pidfile: line1 = server pid, line2 = ssh pid (0 if none) */
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) { fprintf(pf, "%d\n%d\n", getpid(), (int)ssh_pid); fclose(pf); }

    printf("┌─ lanshare ──────────────────────────────\n"
           "│ sharing : %s\n"
           "│ mode    : %s\n"
           "│ pin     : %s\n"
           "│ open    : %s\n"
           "└─────────────────────────────────────────\n",
           cfg.root, cfg.public_url[0] ? "any network (tunnel)" : "LAN",
           cfg.pin_str, url);
    show_qr(url);

    char cp[700];
    snprintf(cp, sizeof cp, "wl-copy '%s' 2>/dev/null &", url);
    if (system(cp)) {}    /* best-effort clipboard */

    for (;;) {
        int conn = accept(lfd, NULL, NULL);
        if (conn < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        pid_t pid = fork();
        if (pid == 0) {
            close(lfd);
            struct timeval tv = {30, 0};   /* 30 s idle reads, not whole-transfer */
            setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            http_serve(conn, &cfg);
            _exit(0);
        }
        close(conn);
    }
}

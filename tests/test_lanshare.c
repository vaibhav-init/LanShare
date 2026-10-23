/* test_lanshare.c — self-check for the non-trivial logic (AGENT.md):
 *   1. path/filename sanitizing          (trust boundary)
 *   2. PIN gate + brute-force lockout    (security)
 *   3. streaming multipart parser, including payloads crafted so that a
 *      boundary marker is SPLIT across internal buffer boundaries
 *      (the bug class the rolling hold-back buffer exists for)
 * Run: make test
 */
#define _GNU_SOURCE  /* mkdtemp */
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/share.h"

#define BOUNDARY "----WebKitFormBoundaryabc123"

static int file_eq(const char *dir, const char *name,
                   const char *want, size_t n)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char got[200000 + 1];
    size_t g = fread(got, 1, sizeof got, f);
    fclose(f);
    return g == n && !memcmp(got, want, n);
}

int main(void)
{
    /* 1. sanitize */
    char out[256];
    extern void sanitize_name_public(const char *, char *, size_t);
    sanitize_name_public("../../etc/passwd", out, sizeof out);
    assert(!strchr(out, '/') && strcmp(out, "passwd") == 0);
    sanitize_name_public("..", out, sizeof out);
    assert(strcmp(out, "upload.bin") == 0);
    sanitize_name_public("a\"b/c\r\nX", out, sizeof out);
    assert(!strchr(out, '"') && !strchr(out, '/'));

    /* 2. pin + lockout */
    Config c = { .root = "/tmp", .pin_str = "4271" };
    static PinState st;                       /* stand-in for the mmap */
    c.pin = &st;
    memset(&st, 0, sizeof st);
    assert(fs_pin_ok(&c, "4271"));
    assert(!fs_pin_ok(&c, "0000"));
    for (int i = 0; i < 4; i++) assert(!fs_pin_ok(&c, "9999"));  /* 5th fail */
    assert(!fs_pin_ok(&c, "4271"));           /* correct but locked out */
    memset(&st, 0, sizeof st);

    /* 3. multipart, two files, boundary split across buffer edges */
    char dir[] = "/tmp/lstest-XXXXXX";
    assert(mkdtemp(dir));
    static char body[400000];
    size_t blen = 0;

    /* payload A: 100k bytes full of decoy boundary prefixes */
    char A[100000];
    for (size_t i = 0; i < sizeof A; i++)
        A[i] = "\r\n--"[i % 4] == '-' && (i % 40 < 6) ? '-' :
               (char)('a' + (i * 7) % 26);

    /* payload B: 50k bytes, ends flush with the final boundary */
    char Bb[50000];
    for (size_t i = 0; i < sizeof Bb; i++) Bb[i] = (char)('0' + i % 10);

    blen += (size_t)snprintf(body + blen, sizeof body - blen,
             "--%s\r\nContent-Disposition: form-data; name=\"file\"; "
             "filename=\"../evil a.bin\"\r\nContent-Type: application/octet-stream"
             "\r\n\r\n", BOUNDARY);
    memcpy(body + blen, A, sizeof A); blen += sizeof A;
    blen += (size_t)snprintf(body + blen, sizeof body - blen,
             "\r\n--%s\r\nContent-Disposition: form-data; "
             "filename=\"two.bin\"\r\n\r\n", BOUNDARY);
    memcpy(body + blen, Bb, sizeof Bb); blen += sizeof Bb;
    blen += (size_t)snprintf(body + blen, sizeof body - blen,
             "\r\n--%s--\r\n", BOUNDARY);

    /* feed through a real file fd so read() semantics match the socket */
    char tmpl[64];
    snprintf(tmpl, sizeof tmpl, "%s/body", dir);
    int bfd = open(tmpl, O_WRONLY | O_CREAT, 0644);
    assert(write(bfd, body, blen) == (ssize_t)blen);
    close(bfd);
    bfd = open(tmpl, O_RDONLY);
    lseek(bfd, 0, SEEK_SET);

    c.root = dir;
    char saved[256];
    int nsaved = fs_save_multipart(bfd, &c, BOUNDARY, blen, "", 0,
                                   saved, sizeof saved);
    close(bfd);

    assert(nsaved == 2);
    assert(file_eq(dir, "evil a.bin", A, sizeof A));       /* sanitized, saved whole */
    assert(file_eq(dir, "two.bin", Bb, sizeof Bb));
    assert(!strcmp(saved, "two.bin"));                     /* last file reported */

    printf("test_lanshare: all asserts passed\n");
    return 0;
}

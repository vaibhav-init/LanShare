/* net.c — listen socket + LAN address discovery */
#define _GNU_SOURCE  /* IFF_LOOPBACK */
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "share.h"

int net_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

/* First real (non-loopback, non-virtual) IPv4 address other devices can use */
int net_lan_ip(char *buf, size_t n)
{
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) < 0) return -1;

    int found = -1;
    for (struct ifaddrs *p = ifs; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        const char *name = p->ifa_name;
        if (!strncmp(name, "lo", 2) || !strncmp(name, "docker", 6) ||
            !strncmp(name, "virbr", 5) || !strncmp(name, "br-", 3))
            continue;
        char ip[INET_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)p->ifa_addr)->sin_addr,
                       ip, sizeof ip)) continue;
        snprintf(buf, n, "%s", ip);
        found = 0;
        break;
    }
    freeifaddrs(ifs);
    return found;
}

void net_client_ip(int sock, char *buf, size_t n)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    if (getpeername(sock, (struct sockaddr *)&sa, &len) == 0)
        inet_ntop(AF_INET, &sa.sin_addr, buf, (socklen_t)n);
    else
        snprintf(buf, n, "?");
}

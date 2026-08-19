// See adb_client.h. Plain POSIX sockets, no dependencies.
#include "adb_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static char g_err[256];

static void set_err(const char *msg) {
    snprintf(g_err, sizeof(g_err), "%s", msg);
}

const char *adb_last_error(void) { return g_err; }

int adb_server_port(void) {
    const char *p = getenv("ADB_SERVER_PORT");
    if (p && *p) {
        int v = atoi(p);
        if (v > 0 && v < 65536) return v;
    }
    return 5037;
}

static int write_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *) buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t) w;
    }
    return 0;
}

static int read_n(int fd, void *buf, size_t n) {
    char *p = (char *) buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;   // unexpected EOF
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (size_t) r;
    }
    return 0;
}

static int connect_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { set_err("socket() failed"); return -1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short) adb_server_port());
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        set_err("cannot reach adb server on 127.0.0.1 (run: adb start-server)");
        close(fd);
        return -1;
    }
    return fd;
}

// Send one length-prefixed request and check the OKAY/FAIL reply.
static int send_request(int fd, const char *req) {
    char hdr[8];
    size_t len = strlen(req);
    if (len > 0xffff) {  // adb encodes the length in exactly 4 hex digits
        set_err("request too long for adb protocol");
        return -1;
    }
    snprintf(hdr, sizeof(hdr), "%04x", (unsigned) len);
    if (write_all(fd, hdr, 4) != 0 || write_all(fd, req, len) != 0) {
        set_err("write to adb server failed");
        return -1;
    }
    char status[4];
    if (read_n(fd, status, 4) != 0) {
        set_err("no reply from adb server");
        return -1;
    }
    if (memcmp(status, "OKAY", 4) == 0) return 0;

    // FAIL: read the length-prefixed reason.
    char lenhex[5] = {0};
    if (read_n(fd, lenhex, 4) == 0) {
        long rl = strtol(lenhex, NULL, 16);
        if (rl > 0 && rl < 240) {
            char reason[256] = {0};
            if (read_n(fd, reason, (size_t) rl) == 0) {
                snprintf(g_err, sizeof(g_err), "adb FAIL: %s", reason);
                return -1;
            }
        }
    }
    set_err("adb request failed");
    return -1;
}

int adb_devices(char *out, size_t out_sz) {
    int fd = connect_server();
    if (fd < 0) return -1;
    if (send_request(fd, "host:devices") != 0) { close(fd); return -1; }
    char lenhex[5] = {0};
    if (read_n(fd, lenhex, 4) != 0) { close(fd); set_err("short devices reply"); return -1; }
    long len = strtol(lenhex, NULL, 16);
    if (len < 0) len = 0;
    if ((size_t) len >= out_sz) len = (long) out_sz - 1;
    if (len > 0 && read_n(fd, out, (size_t) len) != 0) { close(fd); set_err("truncated devices"); return -1; }
    out[len] = '\0';
    close(fd);
    return 0;
}

int adb_shell(const char *serial, const char *cmd,
              char *out, size_t out_sz, size_t *out_len) {
    int fd = connect_server();
    if (fd < 0) return -1;

    char transport[128];
    if (serial && *serial)
        snprintf(transport, sizeof(transport), "host:transport:%s", serial);
    else
        snprintf(transport, sizeof(transport), "host:transport-any");

    if (send_request(fd, transport) != 0) { close(fd); return -1; }

    char svc[4096];
    snprintf(svc, sizeof(svc), "shell:%s", cmd);
    if (send_request(fd, svc) != 0) { close(fd); return -1; }

    // Stream raw output until the shell closes.
    size_t total = 0;
    for (;;) {
        char buf[8192];
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            set_err("read from shell failed");
            close(fd);
            return -1;
        }
        if (out && total < out_sz - 1) {
            size_t room = out_sz - 1 - total;
            size_t take = ((size_t) r < room) ? (size_t) r : room;
            memcpy(out + total, buf, take);
        }
        total += (size_t) r;
    }
    if (out) out[(total < out_sz) ? total : out_sz - 1] = '\0';
    if (out_len) *out_len = total;
    close(fd);
    return 0;
}

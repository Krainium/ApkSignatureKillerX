// seccomp-bpf SIGSYS trap for arm64: intercepts direct syscalls that bypass PLT.
//
// Trapped syscalls:
//  - openat: redirect path from re-signed apk to original
//  - newfstatat: redirect stat path so size/inode match original
//  - statx: same as newfstatat, newer syscall
//
// All trapped syscalls are serviced via openat2 (for opens) or untouched
// syscall numbers (for stats) from the SIGSYS handler to avoid re-trapping.

#include "killerx.h"

#if defined(__aarch64__)

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_newfstatat
#define __NR_newfstatat 79
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_write
#define __NR_write 64
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_lseek
#define __NR_lseek 62
#endif
#ifndef __NR_getpid
#define __NR_getpid 172
#endif
#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

struct kx_open_how {
    unsigned long long flags;
    unsigned long long mode;
    unsigned long long resolve;
};

static long kx_sys4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                 : "memory", "cc");
    return x0;
}

static long kx_sys5(long nr, long a0, long a1, long a2, long a3, long a4) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                 : "memory", "cc");
    return x0;
}

static int kx_streq(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int kx_has_substr(const char *s, const char *sub) {
    if (!s || !sub) return 0;
    int sl = 0, bl = 0;
    for (const char *p = s; *p; p++) sl++;
    for (const char *p = sub; *p; p++) bl++;
    for (int i = 0; i <= sl - bl; i++) {
        int j;
        for (j = 0; j < bl; j++)
            if (s[i + j] != sub[j]) break;
        if (j == bl) return 1;
    }
    return 0;
}

static int kx_ends_with(const char *s, const char *suffix) {
    if (!s || !suffix) return 0;
    int sl = 0, bl = 0;
    for (const char *p = s; *p; p++) sl++;
    for (const char *p = suffix; *p; p++) bl++;
    if (bl > sl) return 0;
    for (int i = 0; i < bl; i++)
        if (s[sl - bl + i] != suffix[i]) return 0;
    return 1;
}

static const char *kx_redirect(const char *path) {
    if (!kx_redirect_active || !path || !kx_rep_path) return path;
    if (kx_apk_path) {
        if (kx_streq(path, kx_apk_path))
            return kx_rep_path;
    } else {
        if (kx_has_substr(path, "/data/app/") && kx_ends_with(path, "/base.apk"))
            return kx_rep_path;
    }
    return path;
}

static long kx_sys2(long nr, long a0, long a1) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1)
                 : "memory", "cc");
    return x0;
}

static long kx_sys3(long nr, long a0, long a1, long a2) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory", "cc");
    return x0;
}

static int kx_is_proc_self(const char *path, const char *suffix) {
    if (!path) return 0;
    if (kx_has_substr(path, "/proc/self/") && kx_ends_with(path, suffix))
        return 1;
    if (kx_has_substr(path, "/proc/") && kx_ends_with(path, suffix)) {
        long pid = kx_sys2(__NR_getpid, 0, 0);
        char pidpath[64];
        int i = 0;
        pidpath[i++] = '/'; pidpath[i++] = 'p'; pidpath[i++] = 'r';
        pidpath[i++] = 'o'; pidpath[i++] = 'c'; pidpath[i++] = '/';
        long p = pid;
        char digits[16]; int d = 0;
        do { digits[d++] = '0' + (p % 10); p /= 10; } while (p > 0);
        while (d > 0) pidpath[i++] = digits[--d];
        pidpath[i++] = '/';
        const char *s = suffix;
        while (*s) pidpath[i++] = *s++;
        pidpath[i] = '\0';
        if (kx_streq(path, pidpath)) return 1;
    }
    return 0;
}

static int kx_stealth_open(const char *path) {
    if (!kx_redirect_active) return -1;
    if (!kx_maps_filter || kx_maps_filter_count == 0) return -1;

    int is_maps = kx_is_proc_self(path, "maps");
    int is_environ = kx_is_proc_self(path, "environ");
    if (!is_maps && !is_environ) return -1;

    struct kx_open_how how = { O_RDONLY, 0, 0 };
    long src_fd = kx_sys4(__NR_openat2, AT_FDCWD, (long)path, (long)&how, (long)sizeof(how));
    if (src_fd < 0) return (int)src_fd;

    char buf[65536];
    long total = 0;
    for (;;) {
        long n = kx_sys3(__NR_read, src_fd, (long)(buf + total), (long)(sizeof(buf) - total - 1));
        if (n <= 0) break;
        total += n;
        if (total >= (long)sizeof(buf) - 1) break;
    }
    kx_sys2(__NR_close, src_fd, 0);
    buf[total] = '\0';

    long mem_fd = kx_sys2(__NR_memfd_create, (long)"", 0);
    if (mem_fd < 0) return -1;

    if (is_maps) {
        char *line = buf;
        while (line < buf + total) {
            char *eol = line;
            while (eol < buf + total && *eol != '\n') eol++;
            if (eol < buf + total) eol++;
            int skip = 0;
            for (int i = 0; i < kx_maps_filter_count; i++) {
                char *p = line;
                const char *pat = kx_maps_filter[i];
                int plen = 0;
                for (const char *q = pat; *q; q++) plen++;
                while (p + plen <= eol) {
                    int j;
                    for (j = 0; j < plen; j++)
                        if (p[j] != pat[j]) break;
                    if (j == plen) { skip = 1; break; }
                    p++;
                }
                if (skip) break;
            }
            if (!skip)
                kx_sys3(__NR_write, mem_fd, (long)line, (long)(eol - line));
            line = eol;
        }
    } else {
        char *p = buf;
        while (p < buf + total) {
            int len = 0;
            while (p + len < buf + total && p[len] != '\0') len++;
            int skip = 0;
            if (len >= 10) {
                const char *ld = "LD_PRELOAD";
                int j;
                for (j = 0; j < 10; j++)
                    if (p[j] != ld[j]) break;
                if (j == 10) skip = 1;
            }
            if (!skip)
                kx_sys3(__NR_write, mem_fd, (long)p, (long)(len + 1));
            p += len + 1;
        }
    }

    kx_sys3(__NR_lseek, mem_fd, 0, SEEK_SET);
    KX_LOGI("stealth: filtered %s via memfd (fd=%ld)", is_maps ? "maps" : "environ", mem_fd);
    return (int)mem_fd;
}

static void handle_openat(ucontext_t *uc) {
    long dirfd = (long) uc->uc_mcontext.regs[0];
    const char *path = (const char *) uc->uc_mcontext.regs[1];
    long flags = (long) uc->uc_mcontext.regs[2];
    long mode = (long) uc->uc_mcontext.regs[3];

    int stealth_fd = kx_stealth_open(path);
    if (stealth_fd >= 0) {
        uc->uc_mcontext.regs[0] = stealth_fd;
        return;
    }

    const char *target = kx_redirect(path);

    struct kx_open_how how;
    how.flags = (unsigned long long) flags;
    how.mode = (flags & (O_CREAT | O_TMPFILE)) ? (unsigned long long) mode : 0ULL;
    how.resolve = 0ULL;

    uc->uc_mcontext.regs[0] = kx_sys4(
        __NR_openat2, dirfd, (long) target, (long) &how, (long) sizeof(how));
}

// newfstatat(dirfd, path, statbuf, flags)
// On arm64, fstat(fd) → fstatat(fd, "", buf, AT_EMPTY_PATH)
// We only redirect path-based calls (non-empty path that matches our apk).
static void handle_newfstatat(ucontext_t *uc) {
    long dirfd = (long) uc->uc_mcontext.regs[0];
    const char *path = (const char *) uc->uc_mcontext.regs[1];
    void *statbuf = (void *) uc->uc_mcontext.regs[2];
    long flags = (long) uc->uc_mcontext.regs[3];

    const char *target = kx_redirect(path);

    // Service via the SAME syscall number but with the redirected path.
    // newfstatat is not trapped by our filter when we use openat2 trick...
    // Actually, we CAN'T re-issue the same trapped syscall from a handler.
    // Instead, use statx (different syscall number) and convert the result.
    //
    // statx(dirfd, path, flags, mask, statxbuf)
    // We issue statx then copy results into the stat buffer.
    // This avoids re-trapping newfstatat.
    char statx_buf[256]; // struct statx is ~256 bytes
    memset(statx_buf, 0, sizeof(statx_buf));

    // STATX_BASIC_STATS = 0x7ff
    long r = kx_sys5(__NR_statx, dirfd, (long) target, flags, 0x7ff, (long) statx_buf);
    if (r < 0) {
        uc->uc_mcontext.regs[0] = r;
        return;
    }

    // statx result to stat conversion:
    // struct statx offsets (from linux/stat.h):
    //   0x00: __u32 stx_mask
    //   0x04: __u32 stx_blksize
    //   0x08: __u64 stx_attributes
    //   0x10: __u32 stx_nlink
    //   0x14: __u32 stx_uid
    //   0x18: __u32 stx_gid
    //   0x1c: __u16 stx_mode
    //   0x28: __u64 stx_ino
    //   0x30: __u64 stx_size
    //   0x38: __u64 stx_blocks
    //
    // struct stat (aarch64):
    //   0x00: __u64 st_dev
    //   0x08: __u64 st_ino
    //   0x10: __u32 st_mode
    //   0x14: __u32 st_nlink
    //   0x18: __u32 st_uid
    //   0x1c: __u32 st_gid
    //   0x20: __u64 st_rdev
    //   0x30: __s64 st_size
    //   0x38: __s32 st_blksize
    //   0x40: __s64 st_blocks

    // Copy relevant fields from statx to stat
    unsigned char *sx = (unsigned char *)statx_buf;
    unsigned char *st = (unsigned char *)statbuf;
    memset(st, 0, 128);

    // st_ino from stx_ino (offset 0x28)
    memcpy(st + 0x08, sx + 0x28, 8);
    // st_mode from stx_mode (offset 0x1c, 2 bytes -> 4 bytes at st+0x10)
    unsigned short mode_val;
    memcpy(&mode_val, sx + 0x1c, 2);
    unsigned int mode32 = mode_val;
    memcpy(st + 0x10, &mode32, 4);
    // st_nlink from stx_nlink (offset 0x10, 4 bytes)
    memcpy(st + 0x14, sx + 0x10, 4);
    // st_uid (offset 0x14)
    memcpy(st + 0x18, sx + 0x14, 4);
    // st_gid (offset 0x18)
    memcpy(st + 0x1c, sx + 0x18, 4);
    // st_size from stx_size (offset 0x30)
    memcpy(st + 0x30, sx + 0x30, 8);
    // st_blksize from stx_blksize (offset 0x04)
    memcpy(st + 0x38, sx + 0x04, 4);
    // st_blocks from stx_blocks (offset 0x38)
    memcpy(st + 0x40, sx + 0x38, 8);

    uc->uc_mcontext.regs[0] = 0;
}

// statx(dirfd, path, flags, mask, statxbuf)
// Already a different syscall, but if trapped we service via... itself.
// Wait - if we trap statx, we can't re-issue it. But we need statx as
// the escape hatch for newfstatat. So we DON'T trap statx.
// Instead we only trap newfstatat and use statx to service it.
// statx calls from userspace will go through PLT hook (read() filter)
// or will get the redirected path from our open hooks.

static void kx_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void) sig;
    ucontext_t *uc = (ucontext_t *) ucv;

    switch (si->si_syscall) {
    case __NR_openat: {
        const char *path = (const char *) uc->uc_mcontext.regs[1];
        const char *target = kx_redirect(path);
        if (target != path)
            KX_LOGI("seccomp openat redirect: %s -> %s", path, target);
        handle_openat(uc);
        break;
    }
    case __NR_newfstatat:
        handle_newfstatat(uc);
        break;
    default:
        KX_LOGW("seccomp: unexpected syscall %d", si->si_syscall);
        uc->uc_mcontext.regs[0] = -ENOSYS;
        break;
    }
}

// Android's zygote installs a system seccomp whitelist; openat2 may not be
// in it (e.g. Pixel 8 Pro / API 34). The raw svc #0 then gets SIGSYS before
// we have our handler up. Probe safely with a temporary handler.
static volatile int kx_probe_trapped = 0;

static void kx_probe_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void) sig; (void) si;
    ucontext_t *uc = (ucontext_t *) ucv;
    kx_probe_trapped = 1;
    uc->uc_mcontext.regs[0] = (unsigned long long) -ENOSYS;
}

static int openat2_supported(void) {
    struct sigaction sa, old;
    sa.sa_sigaction = kx_probe_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, &old);

    kx_probe_trapped = 0;

    struct kx_open_how how;
    how.flags = O_RDONLY;
    how.mode = 0;
    how.resolve = 0;
    long fd = kx_sys4(__NR_openat2, AT_FDCWD, (long) "/dev/null", (long) &how, (long) sizeof(how));

    sigaction(SIGSYS, &old, NULL);

    if (kx_probe_trapped) {
        KX_LOGW("openat2 blocked by system seccomp");
        return 0;
    }
    if (fd == -ENOSYS) return 0;
    if (fd >= 0) kx_sys4(__NR_close, fd, 0, 0, 0);
    return 1;
}

int kx_install_openat2_trap(void) {
    if (!openat2_supported()) {
        KX_LOGW("openat2 unavailable, skipping legacy seccomp trap");
        return 0;
    }

    struct sigaction sa;
    sa.sa_sigaction = kx_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) {
        KX_LOGE("sigaction(SIGSYS) failed");
        return 0;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        KX_LOGE("PR_SET_NO_NEW_PRIVS failed");
        return 0;
    }

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    };
    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        KX_LOGE("PR_SET_SECCOMP failed");
        return 0;
    }

    KX_LOGI("legacy seccomp trap installed (openat2 escape hatch)");
    return 1;
}

int kx_install_syscall_trap(void) {
    // Try the multi-method SVC killer first (no openat2 needed)
    if (kx_install_svc_killer()) return 1;

    // Fall back to legacy openat2-based seccomp trap
    return kx_install_openat2_trap();
}

#else // not arm64

int kx_install_syscall_trap(void) {
    KX_LOGW("syscall trap only implemented for arm64");
    return 0;
}

int kx_install_openat2_trap(void) {
    return 0;
}

#endif

// kx_seccomp_test — standalone proof, on a real arm64 kernel, that the KillerX
// seccomp trap catches a DIRECT `svc` openat (the read that defeats a PLT-only
// killer) and redirects it to the replacement file.
//
// It is the same mechanism as killerx/src/main/cpp/seccomp_trap.c, distilled to a
// dependency-free Linux program so it can run on the Graviton host or inside a
// redroid shell without the whole Android app.
//
// What it does:
//   1. write REAL_MARKER to a "real" file and FAKE_MARKER to a "fake" file
//   2. install the openat trap (real -> fake)
//   3. open the real file with a hand-written svc openat, read it
//   4. PASS if it read FAKE (redirect held on a direct syscall), FAIL if REAL
//
// arm64 only; on other arches it prints SKIP.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#if defined(__aarch64__)

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <ucontext.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

struct kx_open_how {
    unsigned long long flags, mode, resolve;
};

static const char *g_real = NULL;
static const char *g_fake = NULL;

static long kx_sys4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

static int streq(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void on_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void) sig;
    ucontext_t *uc = (ucontext_t *) ucv;
    if (si->si_syscall != __NR_openat) {
        uc->uc_mcontext.regs[0] = -ENOSYS;
        return;
    }
    long dirfd = (long) uc->uc_mcontext.regs[0];
    const char *path = (const char *) uc->uc_mcontext.regs[1];
    long flags = (long) uc->uc_mcontext.regs[2];
    long mode = (long) uc->uc_mcontext.regs[3];

    const char *target = path;
    if (path && g_real && streq(path, g_real)) target = g_fake;

    struct kx_open_how how;
    how.flags = (unsigned long long) flags;
    how.mode = (flags & (O_CREAT | O_TMPFILE)) ? (unsigned long long) mode : 0ULL;
    how.resolve = 0ULL;
    uc->uc_mcontext.regs[0] =
        kx_sys4(__NR_openat2, dirfd, (long) target, (long) &how, (long) sizeof(how));
}

static int openat2_supported(void) {
    struct kx_open_how how = {O_RDONLY, 0, 0};
    long fd = kx_sys4(__NR_openat2, AT_FDCWD, (long) "/dev/null", (long) &how, (long) sizeof(how));
    if (fd == -ENOSYS) return 0;
    if (fd >= 0) kx_sys4(__NR_close, fd, 0, 0, 0);
    return 1;
}

static int install_trap(void) {
    if (!openat2_supported()) {
        printf("SKIP: openat2 unavailable on this kernel\n");
        return -1;
    }
    struct sigaction sa;
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

// direct svc openat, bypassing libc (the anti-killer read).
static int svc_open(const char *path) {
    return (int) kx_sys4(__NR_openat, AT_FDCWD, (long) path, O_RDONLY, 0);
}

int main(void) {
    char real_path[] = "/tmp/kx_real_XXXXXX";
    char fake_path[] = "/tmp/kx_fake_XXXXXX";
    int rfd = mkstemp(real_path);
    int ffd = mkstemp(fake_path);
    if (rfd < 0 || ffd < 0) { perror("mkstemp"); return 2; }
    write(rfd, "REAL", 4);
    write(ffd, "FAKE", 4);
    close(rfd);
    close(ffd);
    g_real = real_path;
    g_fake = fake_path;

    printf("real file: %s (REAL)\n", real_path);
    printf("fake file: %s (FAKE)\n", fake_path);

    // baseline: direct svc open before the trap sees the REAL bytes.
    int b = svc_open(real_path);
    char pre[8] = {0};
    if (b >= 0) { read(b, pre, 4); close(b); }
    printf("before trap, direct svc read: %s\n", pre);

    if (install_trap() != 0) {
        printf("could not install seccomp trap (need CAP or newer kernel)\n");
        unlink(real_path); unlink(fake_path);
        return 2;
    }
    printf("seccomp openat trap installed\n");

    // the real test: direct svc openat on the real file, post-trap.
    int fd = svc_open(real_path);
    char got[8] = {0};
    if (fd >= 0) { read(fd, got, 4); close(fd); }
    printf("after trap, direct svc read:  %s\n", got);

    // also confirm a normal libc open is redirected.
    int lf = open(real_path, O_RDONLY);
    char lgot[8] = {0};
    if (lf >= 0) { read(lf, lgot, 4); close(lf); }
    printf("after trap, libc open read:   %s\n", lgot);

    int pass = (strncmp(got, "FAKE", 4) == 0) && (strncmp(lgot, "FAKE", 4) == 0);
    unlink(real_path);
    unlink(fake_path);
    printf("\n%s: direct svc syscall %s redirected by the seccomp trap\n",
           pass ? "PASS" : "FAIL", pass ? "WAS" : "was NOT");
    return pass ? 0 : 1;
}

#else // not arm64

int main(void) {
    printf("SKIP: kx_seccomp_test is arm64 only (this host is not aarch64)\n");
    return 0;
}

#endif

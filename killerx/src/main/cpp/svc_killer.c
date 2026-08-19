// SVC interception for arm64 — defeats direct-syscall APK reads.
//
//  1. SVC binary patching — replace svc #0 in loaded .so with B <trampoline>
//  2. Seccomp openat redirect — SIGSYS trap + openat2 escape for non-matching
//  3. Antikill seccomp — SECCOMP_RET_ERRNO for kill/tgkill targeting self

#include "killerx.h"

#if defined(__aarch64__)

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
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
#ifndef __NR_dup
#define __NR_dup 23
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// ─── ARM64 INSTRUCTION ENCODING ────────────────────────────────────────

#define A64_SVC_0     0xD4000001u
#define A64_NOP       0xD503201Fu
#define A64_SVC_MASK  0xFFE0001Fu  // matches all SVC #imm16

static inline uint32_t a64_cmp_x_imm(int rn, int imm12) {
    return 0xF100001Fu | ((uint32_t)imm12 << 10) | ((uint32_t)rn << 5);
}
static inline uint32_t a64_b(int64_t byte_offset) {
    return 0x14000000u | (((uint32_t)(byte_offset >> 2)) & 0x03FFFFFFu);
}
static inline uint32_t a64_b_eq(int64_t byte_offset) {
    return 0x54000000u | ((((uint32_t)(byte_offset >> 2)) & 0x7FFFFu) << 5);
}
static inline uint32_t a64_ldr_x_pcrel(int rt, int64_t byte_offset) {
    return 0x58000000u | ((((uint32_t)(byte_offset >> 2)) & 0x7FFFFu) << 5) | (uint32_t)rt;
}
static inline uint32_t a64_br(int rn) {
    return 0xD61F0000u | ((uint32_t)rn << 5);
}
static inline uint32_t a64_blr(int rn) {
    return 0xD63F0000u | ((uint32_t)rn << 5);
}
static inline uint32_t a64_mov_x_x(int rd, int rm) {
    return 0xAA0003E0u | ((uint32_t)rm << 16) | (uint32_t)rd;
}
static inline uint32_t a64_sub_sp_imm(int imm12) {
    return 0xD10003FFu | ((uint32_t)imm12 << 10);
}
static inline uint32_t a64_add_sp_imm(int imm12) {
    return 0x910003FFu | ((uint32_t)imm12 << 10);
}
static inline uint32_t a64_stp(int rt1, int rt2, int rn, int offset) {
    uint32_t imm7 = (uint32_t)((offset / 8) & 0x7F);
    return 0xA9000000u | (imm7 << 15) | ((uint32_t)rt2 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt1;
}
static inline uint32_t a64_ldp(int rt1, int rt2, int rn, int offset) {
    uint32_t imm7 = (uint32_t)((offset / 8) & 0x7F);
    return 0xA9400000u | (imm7 << 15) | ((uint32_t)rt2 << 10) | ((uint32_t)rn << 5) | (uint32_t)rt1;
}
static inline uint32_t a64_str_x(int rt, int rn, int offset) {
    return 0xF9000000u | ((uint32_t)(offset / 8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
static inline uint32_t a64_ldr_x(int rt, int rn, int offset) {
    return 0xF9400000u | ((uint32_t)(offset / 8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}

static inline int a64_b_in_range(int64_t byte_offset) {
    return byte_offset >= -128 * 1024 * 1024 && byte_offset < 128 * 1024 * 1024;
}

// ─── RAW SYSCALL ────────────────────────────────────────────────────────

static long kx_raw_svc(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory", "cc");
    return x0;
}

// ─── SHARED STATE ───────────────────────────────────────────────────────

static int kx_origin_fd = -1;         // pre-opened origin.apk fd


// ─── SVC HANDLER (shared by all methods) ────────────────────────────────


static int kx_path_eq(const char *a, const char *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int kx_path_match(const char *path) {
    if (!path) return 0;
    if (kx_apk_path)
        return kx_path_eq(path, kx_apk_path);
    if (!strstr(path, "/data/app/")) return 0;
    size_t len = strlen(path);
    return len >= 9 && strcmp(path + len - 9, "/base.apk") == 0;
}

// Handle redirected stat via statx (not trapped by our filter)
static long kx_stat_origin(long dirfd, void *statbuf, long flags) {
    (void)dirfd;
    char sxbuf[256];
    memset(sxbuf, 0, sizeof(sxbuf));
    long r = kx_raw_svc(__NR_statx, kx_origin_fd, (long)"",
                        AT_EMPTY_PATH, 0x7ff, (long)sxbuf, 0);
    if (r < 0) return r;
    unsigned char *sx = (unsigned char *)sxbuf;
    unsigned char *st = (unsigned char *)statbuf;
    memset(st, 0, 128);
    memcpy(st + 0x08, sx + 0x28, 8);   // st_ino
    unsigned short m; memcpy(&m, sx + 0x1c, 2);
    unsigned int m32 = m; memcpy(st + 0x10, &m32, 4); // st_mode
    memcpy(st + 0x14, sx + 0x10, 4);   // st_nlink
    memcpy(st + 0x18, sx + 0x14, 4);   // st_uid
    memcpy(st + 0x1c, sx + 0x18, 4);   // st_gid
    memcpy(st + 0x30, sx + 0x30, 8);   // st_size
    memcpy(st + 0x38, sx + 0x04, 4);   // st_blksize
    memcpy(st + 0x40, sx + 0x38, 8);   // st_blocks
    (void)flags;
    return 0;
}

// Central handler called by SVC trampoline and runtime methods
long kx_handle_svc(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
    if (nr == __NR_openat) {
        if (kx_path_match((const char *)a1)) {
            if (kx_origin_fd >= 0)
                return kx_raw_svc(__NR_dup, kx_origin_fd, 0, 0, 0, 0, 0);
            const char *rp = kx_rep_path ? kx_rep_path : (const char *)a1;
            return kx_raw_svc(nr, a0, (long)rp, a2, a3, a4, a5);
        }
        return kx_raw_svc(nr, a0, a1, a2, a3, a4, a5);
    }
    if (nr == __NR_newfstatat) {
        if (kx_path_match((const char *)a1)) {
            if (kx_origin_fd >= 0)
                return kx_stat_origin(a0, (void *)a2, a3);
            const char *rp = kx_rep_path ? kx_rep_path : (const char *)a1;
            return kx_raw_svc(nr, a0, (long)rp, a2, a3, a4, a5);
        }
        return kx_raw_svc(nr, a0, a1, a2, a3, a4, a5);
    }

    // RASP termination blocking (direct SVC bypass of libc)
    if (kx_rasp_hooks_active) {
        if (nr == 93 || nr == 94) { // exit / exit_group
            KX_LOGW("blocked exit syscall %ld via SVC trap", nr);
            return 0;
        }
        if (nr == 129) { // kill
            pid_t pid = (pid_t)a0;
            int sig = (int)a1;
            if (pid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
                KX_LOGW("blocked kill(%d, %d) via SVC trap", pid, sig);
                return 0;
            }
        }
        if (nr == 131) { // tgkill
            int tgid = (int)a0;
            int sig = (int)a2;
            if (tgid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
                KX_LOGW("blocked tgkill(sig=%d) via SVC trap", sig);
                return 0;
            }
        }
    }

    return kx_raw_svc(nr, a0, a1, a2, a3, a4, a5);
}

// ═══════════════════════════════════════════════════════════════════════
// METHOD 1: SVC BINARY PATCHING
// ═══════════════════════════════════════════════════════════════════════

#define MAX_REGIONS   256
#define MAX_SITES     8192
#define STUB_WORDS  22         // expanded stub (88 bytes): 6 syscall checks
#define HANDLER_WORDS 40
#define HANDLER_BYTES (HANDLER_WORDS * 4)
#define TRAMP_PAGE    131072   // 128KB per trampoline page
#define B_RANGE       (128 * 1024 * 1024)  // ±128MB

struct svc_site {
    uintptr_t addr;
};

static struct svc_site kx_sites[MAX_SITES];
static int kx_site_count = 0;

// Trampoline pages (for cleanup/future patching)
#define MAX_TRAMP_PAGES 64
static void *kx_tramp_pages[MAX_TRAMP_PAGES];
static int kx_tramp_count = 0;

// Shared intercept handler address (in first trampoline page)
static uintptr_t kx_shared_handler_addr = 0;

// Track already-patched memory regions so rescan skips them
struct patched_region {
    uintptr_t start, end;
};
#define MAX_PATCHED_REGIONS 256
static struct patched_region kx_patched[MAX_PATCHED_REGIONS];
static int kx_patched_count = 0;
static pthread_mutex_t kx_patch_lock = PTHREAD_MUTEX_INITIALIZER;

static void mark_patched(uintptr_t start, uintptr_t end) {
    if (kx_patched_count < MAX_PATCHED_REGIONS) {
        kx_patched[kx_patched_count].start = start;
        kx_patched[kx_patched_count].end = end;
        kx_patched_count++;
    }
}

static int already_patched(uintptr_t start, uintptr_t end) {
    for (int i = 0; i < kx_patched_count; i++) {
        if (kx_patched[i].start == start && kx_patched[i].end == end)
            return 1;
    }
    return 0;
}

static int is_excluded(const char *line) {
    if (!line) return 1;
    if (strstr(line, "libkillerx.so")) return 1;
    if (strstr(line, "libbytehook.so")) return 1;
    if (strstr(line, "libshadowhook.so")) return 1;
    if (strstr(line, "/system/")) return 1;
    if (strstr(line, "/apex/")) return 1;
    if (strstr(line, "/vendor/")) return 1;
    if (strstr(line, "/product/")) return 1;
    if (strstr(line, "linker64")) return 1;
    if (strstr(line, "[vdso]")) return 1;
    if (strstr(line, "[vvar]")) return 1;
    if (strstr(line, "[anon:")) return 1;
    if (strstr(line, "[stack")) return 1;
    if (!strstr(line, ".so")) return 1;
    return 0;
}

static int scan_region(uintptr_t start, uintptr_t end, int base_idx) {
    int found = 0;
    uint32_t *p = (uint32_t *)start;
    uint32_t *pe = (uint32_t *)end;
    while (p < pe && (base_idx + found) < MAX_SITES) {
        if ((*p & A64_SVC_MASK) == A64_SVC_0) {
            kx_sites[base_idx + found].addr = (uintptr_t)p;
            found++;
        }
        p++;
    }
    return found;
}

// Generate shared intercept handler at the start of a trampoline page.
// x16 = return address, all other regs = original caller values.
static int gen_shared_handler(uint32_t *code, uintptr_t handler_func) {
    int i = 0;
    code[i++] = a64_sub_sp_imm(176);
    code[i++] = a64_stp(0, 1, 31, 0);
    code[i++] = a64_stp(2, 3, 31, 16);
    code[i++] = a64_stp(4, 5, 31, 32);
    code[i++] = a64_stp(6, 7, 31, 48);
    code[i++] = a64_stp(8, 9, 31, 64);
    code[i++] = a64_stp(10, 11, 31, 80);
    code[i++] = a64_stp(12, 13, 31, 96);
    code[i++] = a64_stp(14, 15, 31, 112);
    code[i++] = a64_stp(16, 17, 31, 128);
    code[i++] = a64_stp(18, 29, 31, 144);
    code[i++] = a64_str_x(30, 31, 160);

    code[i++] = a64_mov_x_x(6, 5);
    code[i++] = a64_mov_x_x(5, 4);
    code[i++] = a64_mov_x_x(4, 3);
    code[i++] = a64_mov_x_x(3, 2);
    code[i++] = a64_mov_x_x(2, 1);
    code[i++] = a64_mov_x_x(1, 0);
    code[i++] = a64_mov_x_x(0, 8);

    int ldr_idx = i;
    code[i++] = 0; // patched below
    code[i++] = a64_blr(16);

    code[i++] = a64_ldr_x(16, 31, 128);
    code[i++] = a64_ldr_x(17, 31, 136);
    code[i++] = a64_ldp(18, 29, 31, 144);
    code[i++] = a64_ldr_x(30, 31, 160);
    code[i++] = a64_ldp(14, 15, 31, 112);
    code[i++] = a64_ldp(12, 13, 31, 96);
    code[i++] = a64_ldp(10, 11, 31, 80);
    code[i++] = a64_ldp(8, 9, 31, 64);
    code[i++] = a64_ldp(6, 7, 31, 48);
    code[i++] = a64_ldp(4, 5, 31, 32);
    code[i++] = a64_ldp(2, 3, 31, 16);
    code[i++] = a64_ldr_x(1, 31, 8);
    code[i++] = a64_add_sp_imm(176);
    code[i++] = a64_br(16);

    if (i & 1) code[i++] = A64_NOP;

    int pool_idx = i;
    uint64_t hf = (uint64_t)handler_func;
    code[i++] = (uint32_t)(hf & 0xFFFFFFFF);
    code[i++] = (uint32_t)(hf >> 32);

    int64_t ldr_off = (int64_t)(pool_idx - ldr_idx) * 4;
    code[ldr_idx] = a64_ldr_x_pcrel(16, ldr_off);

    return i;
}

// Generate per-site stub that checks 6 syscall numbers.
// Layout (88 bytes = 22 words):
//   [0..11]  6x (cmp x8, #NR; b.eq intercept)
//   [12]     svc #0 (passthrough)
//   [13]     B <return> (relative)
//   [14..16] ldr x16,pool; ldr x17,pool; br x17
//   [17]     NOP (align)
//   [18..21] literal pool: return_addr, handler_addr
static int gen_stub(uint32_t *code, uintptr_t svc_addr, uintptr_t stub_addr,
                    uintptr_t handler_addr) {
    uintptr_t return_addr = svc_addr + 4;
    static const int checked[] = { 56, 79, 93, 94, 129, 131 };
    int nc = 6;
    int intercept = nc * 2 + 2; // index 14

    int i = 0;
    int beq_idx[6];
    for (int c = 0; c < nc; c++) {
        code[i++] = a64_cmp_x_imm(8, checked[c]);
        beq_idx[c] = i;
        code[i++] = 0; // placeholder
    }
    code[i++] = A64_SVC_0; // [12]
    int64_t ret_off = (int64_t)return_addr - (int64_t)(stub_addr + (uint64_t)i * 4);
    code[i++] = a64_b(ret_off); // [13]

    // intercept path
    int ldr16 = i;
    code[i++] = 0; // [14]
    int ldr17 = i;
    code[i++] = 0; // [15]
    code[i++] = a64_br(17); // [16]
    code[i++] = A64_NOP;    // [17]

    // pool
    int pool_ret = i; // [18]
    uint64_t ra = (uint64_t)return_addr;
    code[i++] = (uint32_t)(ra & 0xFFFFFFFF);
    code[i++] = (uint32_t)(ra >> 32);
    int pool_hnd = i; // [20]
    uint64_t ha = (uint64_t)handler_addr;
    code[i++] = (uint32_t)(ha & 0xFFFFFFFF);
    code[i++] = (uint32_t)(ha >> 32);

    for (int c = 0; c < nc; c++)
        code[beq_idx[c]] = a64_b_eq((int64_t)(intercept - beq_idx[c]) * 4);
    code[ldr16] = a64_ldr_x_pcrel(16, (int64_t)(pool_ret - ldr16) * 4);
    code[ldr17] = a64_ldr_x_pcrel(17, (int64_t)(pool_hnd - ldr17) * 4);
    return i;
}

// Try MAP_FIXED_NOREPLACE first (kernel 4.17+), then hint-based fallback
static void *mmap_near(uintptr_t target, size_t size) {
    uintptr_t base = target & ~(uintptr_t)0xFFF;

    // Phase 1: MAP_FIXED_NOREPLACE at precise addresses
    for (uintptr_t off = 0; off < (uintptr_t)B_RANGE; off += 65536) {
        void *p;
        if (off == 0) {
            p = mmap((void *)base, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        } else {
            uintptr_t above = base + off;
            p = mmap((void *)above, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p == MAP_FAILED && base >= off) {
                uintptr_t below = base - off;
                p = mmap((void *)below, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            }
        }
        if (p != MAP_FAILED) {
            int64_t dist = (int64_t)((uintptr_t)p - target);
            if (dist < 0) dist = -dist;
            if ((uint64_t)dist < (uint64_t)B_RANGE)
                return p;
            munmap(p, size);
        }
    }

    // Phase 2: hint-based fallback (MAP_FIXED_NOREPLACE unsupported)
    for (uintptr_t off = 0; off < (uintptr_t)B_RANGE; off += 4096) {
        void *p;
        if (off == 0) {
            p = mmap((void *)(base), size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        } else {
            p = mmap((void *)(base + off), size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED || (uintptr_t)p - target > (uintptr_t)B_RANGE) {
                if (p != MAP_FAILED) munmap(p, size);
                if (base >= off) {
                    p = mmap((void *)(base - off), size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                } else {
                    continue;
                }
            }
        }
        if (p != MAP_FAILED) {
            int64_t dist = (int64_t)((uintptr_t)p - target);
            if (dist < 0) dist = -dist;
            if ((uint64_t)dist < (uint64_t)B_RANGE)
                return p;
            munmap(p, size);
        }
    }
    return MAP_FAILED;
}

// Patch a batch of SVC sites into a single trampoline page.
// Returns number of sites patched.
static int patch_sites_batch(struct svc_site *sites, int count, uintptr_t handler) {
    if (count == 0) return 0;
    if (kx_tramp_count >= MAX_TRAMP_PAGES) {
        KX_LOGW("svc patch: max trampoline pages reached");
        return 0;
    }

    uintptr_t center = sites[count / 2].addr;
    void *tramp = mmap_near(center, TRAMP_PAGE);
    if (tramp == MAP_FAILED) {
        KX_LOGW("svc patch: mmap trampoline near %p failed", (void *)center);
        return 0;
    }

    uint32_t *code = (uint32_t *)tramp;
    int code_offset = 0;

    // If this is the first trampoline page, generate the shared handler here
    if (kx_shared_handler_addr == 0) {
        int hw = gen_shared_handler(code, handler);
        kx_shared_handler_addr = (uintptr_t)tramp;
        code_offset = (hw + 1) & ~1; // align to 8 bytes
    }

    int patched = 0;
    // Track stub offsets for each site so we can do the actual patching
    int stub_offsets[MAX_SITES];

    for (int s = 0; s < count; s++) {
        uintptr_t svc_addr = sites[s].addr;
        uintptr_t stub_addr = (uintptr_t)tramp + (uint64_t)code_offset * 4;

        // Check svc_addr → stub_addr is within B range
        int64_t dist = (int64_t)(stub_addr - svc_addr);
        if (!a64_b_in_range(dist)) {
            stub_offsets[s] = -1;
            continue;
        }

        // Check if we have room in the trampoline page
        int stub_words = gen_stub(code + code_offset, svc_addr, stub_addr,
                                  kx_shared_handler_addr);
        if ((code_offset + stub_words) * 4 > TRAMP_PAGE) {
            KX_LOGW("svc patch: trampoline page full at %d sites", patched);
            stub_offsets[s] = -1;
            break;
        }

        stub_offsets[s] = code_offset;
        code_offset += stub_words;
        patched++;
    }

    // Make trampoline page executable
    mprotect(tramp, TRAMP_PAGE, PROT_READ | PROT_EXEC);
    __builtin___clear_cache(tramp, (char *)tramp + TRAMP_PAGE);
    kx_tramp_pages[kx_tramp_count++] = tramp;

    // Now patch the actual SVC sites to branch to their stubs
    for (int s = 0; s < count && s < patched + count; s++) {
        if (stub_offsets[s] < 0) continue;
        uintptr_t svc_addr = sites[s].addr;
        uintptr_t stub_addr = (uintptr_t)tramp + (uint64_t)stub_offsets[s] * 4;

        int64_t dist = (int64_t)(stub_addr - svc_addr);
        if (!a64_b_in_range(dist)) continue;

        uintptr_t page = svc_addr & ~(uintptr_t)0xFFF;
        if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0) {
            KX_LOGW("svc patch: mprotect RW failed for %p", (void *)svc_addr);
            continue;
        }

        *(volatile uint32_t *)svc_addr = a64_b(dist);

        mprotect((void *)page, 4096, PROT_READ | PROT_EXEC);
        __builtin___clear_cache((void *)svc_addr, (char *)svc_addr + 4);
    }

    return patched;
}

// Internal: scan maps and patch any new SVC sites. Returns total newly patched.
static int do_svc_patching(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[512];

    struct { uintptr_t start, end; } regions[MAX_REGIONS];
    int rcount = 0;

    while (fgets(line, sizeof(line), maps) && rcount < MAX_REGIONS) {
        uintptr_t start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (perms[2] != 'x') continue;
        if (is_excluded(line)) continue;
        if (end - start < 64) continue;
        if (already_patched(start, end)) continue;
        regions[rcount].start = start;
        regions[rcount].end = end;
        rcount++;
    }
    fclose(maps);

    if (rcount == 0) return 0;

    // Scan all candidate regions for SVC instructions
    int base = kx_site_count;
    int new_sites = 0;
    for (int r = 0; r < rcount; r++) {
        new_sites += scan_region(regions[r].start, regions[r].end,
                                 base + new_sites);
        mark_patched(regions[r].start, regions[r].end);
    }
    kx_site_count = base + new_sites;

    if (new_sites == 0) {
        KX_LOGI("svc scan: no svc sites found in %d new regions", rcount);
        return 0;
    }

    KX_LOGI("svc scan: found %d svc sites in %d regions", new_sites, rcount);

    // Group sites by proximity for multi-trampoline-page allocation.
    // Sort sites by address, then split into groups where consecutive
    // sites are within B_RANGE of each other.
    struct svc_site *new_start = &kx_sites[base];

    // Simple insertion sort (usually small count)
    for (int i = 1; i < new_sites; i++) {
        struct svc_site tmp = new_start[i];
        int j = i - 1;
        while (j >= 0 && new_start[j].addr > tmp.addr) {
            new_start[j + 1] = new_start[j];
            j--;
        }
        new_start[j + 1] = tmp;
    }

    // Split into groups: each group's sites are within ±120MB of the group center
    // (leaving 8MB margin for the trampoline page offset)
    int total_patched = 0;
    int group_start = 0;
    while (group_start < new_sites) {
        uintptr_t first = new_start[group_start].addr;
        int group_end = group_start + 1;
        while (group_end < new_sites &&
               new_start[group_end].addr - first < 120UL * 1024 * 1024) {
            group_end++;
        }

        int group_count = group_end - group_start;
        total_patched += patch_sites_batch(&new_start[group_start], group_count,
                                           (uintptr_t)kx_handle_svc);
        group_start = group_end;
    }

    KX_LOGI("svc patch: %d sites patched with trampolines", total_patched);
    return total_patched;
}

static int try_svc_patching(void) {
    return do_svc_patching();
}

// ═══════════════════════════════════════════════════════════════════════
// METHOD 2: SECCOMP + PRE-OPENED FD + HELPER THREAD (Snowblind-style)
// ═══════════════════════════════════════════════════════════════════════

// openat2 escape struct (kernel 5.6+)
struct kx_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

static volatile int kx_seccomp_redirect_logged = 0;

static void seccomp_sigsys(int sig, siginfo_t *si, void *ucv) {
    (void)sig;
    ucontext_t *uc = (ucontext_t *)ucv;
    long nr = si->si_syscall;

    if (nr == __NR_openat) {
        const char *path = (const char *)uc->uc_mcontext.regs[1];
        if (kx_path_match(path) && kx_origin_fd >= 0) {
            if (!kx_seccomp_redirect_logged) {
                kx_seccomp_redirect_logged = 1;
                KX_LOGI("seccomp redirect: openat base.apk -> origin (fd %d)", kx_origin_fd);
            }
            uc->uc_mcontext.regs[0] = (uint64_t)kx_raw_svc(
                __NR_dup, kx_origin_fd, 0, 0, 0, 0, 0);
            return;
        }
        // Non-matching path: escape via openat2 (different syscall nr, not in our filter)
        struct kx_open_how how = {0};
        how.flags = uc->uc_mcontext.regs[2];
        how.mode = (how.flags & (O_CREAT | __O_TMPFILE)) ? (uc->uc_mcontext.regs[3] & 07777) : 0;
        long result = kx_raw_svc(
            __NR_openat2,
            (long)uc->uc_mcontext.regs[0],
            (long)path,
            (long)&how, (long)sizeof(how), 0, 0);
        uc->uc_mcontext.regs[0] = (uint64_t)result;
        return;
    }

    if (nr == __NR_newfstatat) {
        const char *path = (const char *)uc->uc_mcontext.regs[1];
        if (kx_path_match(path) && kx_origin_fd >= 0) {
            uc->uc_mcontext.regs[0] = (uint64_t)kx_stat_origin(
                (long)uc->uc_mcontext.regs[0],
                (void *)uc->uc_mcontext.regs[2],
                (long)uc->uc_mcontext.regs[3]);
            return;
        }
        // Non-matching: escape via statx (different syscall nr, not in our filter)
        char sxbuf[256];
        memset(sxbuf, 0, sizeof(sxbuf));
        long r = kx_raw_svc(__NR_statx,
            (long)uc->uc_mcontext.regs[0],
            (long)path,
            (long)uc->uc_mcontext.regs[3],
            0x7ff, (long)sxbuf, 0);
        if (r == 0) {
            unsigned char *sx = (unsigned char *)sxbuf;
            unsigned char *st = (unsigned char *)uc->uc_mcontext.regs[2];
            memset(st, 0, 128);
            memcpy(st + 0x08, sx + 0x28, 8);
            unsigned short m; memcpy(&m, sx + 0x1c, 2);
            unsigned int m32 = m; memcpy(st + 0x10, &m32, 4);
            memcpy(st + 0x14, sx + 0x10, 4);
            memcpy(st + 0x18, sx + 0x14, 4);
            memcpy(st + 0x1c, sx + 0x18, 4);
            memcpy(st + 0x30, sx + 0x30, 8);
            memcpy(st + 0x38, sx + 0x04, 4);
            memcpy(st + 0x40, sx + 0x38, 8);
        }
        uc->uc_mcontext.regs[0] = (uint64_t)r;
        return;
    }

    uc->uc_mcontext.regs[0] = (uint64_t)-ENOSYS;
}

// Install seccomp filter that traps openat/newfstatat and redirects
// matching base.apk accesses to origin.apk via SIGSYS handler.
// Non-matching paths escape through openat2/statx (different syscall nrs).
int kx_install_seccomp_redirect(void) {
    if (kx_rep_path && kx_origin_fd < 0)
        kx_origin_fd = open(kx_rep_path, O_RDONLY);

    // Verify openat2 is available (our escape hatch for non-matching paths)
    struct kx_open_how test_how = {O_RDONLY, 0, 0};
    long test = kx_raw_svc(__NR_openat2, AT_FDCWD, (long)"/dev/null",
                           (long)&test_how, (long)sizeof(test_how), 0, 0);
    if (test == -ENOSYS) {
        KX_LOGW("seccomp redirect: openat2 unavailable (kernel too old), skipping");
        return 0;
    }
    if (test >= 0)
        kx_raw_svc(__NR_close, test, 0, 0, 0, 0, 0);

    // Install SIGSYS handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = seccomp_sigsys;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) {
        KX_LOGE("seccomp redirect: sigaction SIGSYS failed");
        return 0;
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // BPF: trap openat(56) and newfstatat(79) for aarch64, allow everything else
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
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        KX_LOGE("seccomp redirect: install failed: %s", strerror(errno));
        return 0;
    }

    KX_LOGI("seccomp redirect: active (openat2 escape, origin fd=%d)", kx_origin_fd);
    return 1;
}


// ═══════════════════════════════════════════════════════════════════════
// ANTI-KILL SECCOMP FILTER (blocks raw SVC kill/tgkill targeting self)
// ═══════════════════════════════════════════════════════════════════════

// BPF filter that returns EPERM for kill(self, SIGKILL/SIGTERM/SIGABRT)
// and tgkill(self, *, SIGKILL/SIGTERM/SIGABRT). This catches dynamically
// generated SVC instructions that bypass PLT hooks.
// Uses SECCOMP_RET_ERRNO — no SIGSYS handler needed, no recursion.

#ifndef SECCOMP_RET_ERRNO
#define SECCOMP_RET_ERRNO  0x00050000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW  0x7fff0000U
#endif

static int install_antikill_seccomp(void) {
    pid_t self = getpid();
    uint32_t neg_self = (uint32_t)(-(int32_t)self);
    uint32_t neg_one  = (uint32_t)-1;

    struct sock_filter filter[] = {
        /* 0*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                     // Load nr
        /* 1*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 10),     // kill→2, else→12
        /* 2*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),                    // Load pid
        /* 3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)self, 3, 0), // pid=self→7
        /* 4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),             // pid=0→7
        /* 5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, neg_self, 1, 0),      // pid=-self→7
        /* 6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, neg_one, 0, 14),      // pid=-1→7, else→21
        /* 7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 24),                    // Load sig
        /* 8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 2, 0),       // →11
        /* 9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTERM, 1, 0),       // →11
        /*10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 10),      // →11, else→21
        /*11*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),      // BLOCK kill
        /*12*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),                     // Reload nr
        /*13*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 7),   // tgkill→14, else→21
        /*14*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16),                    // Load tgid
        /*15*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)self, 0, 5), // self→16, else→21
        /*16*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 32),                    // Load sig (args[2])
        /*17*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 2, 0),       // →20
        /*18*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTERM, 1, 0),       // →20
        /*19*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 1),       // →20, else→21
        /*20*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),      // BLOCK tgkill
        /*21*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),              // ALLOW
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    // Need NO_NEW_PRIVS before installing seccomp
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        KX_LOGW("antikill seccomp: PR_SET_NO_NEW_PRIVS failed: %s", strerror(errno));
        // May already be set, continue anyway
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        KX_LOGW("antikill seccomp: install failed: %s", strerror(errno));
        return 0;
    }

    KX_LOGI("antikill seccomp: installed (blocks kill/tgkill self with SIGKILL/SIGTERM/SIGABRT)");
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════

int kx_install_svc_killer(void) {
    if (kx_rep_path && kx_origin_fd < 0)
        kx_origin_fd = open(kx_rep_path, O_RDONLY);

    int patched = try_svc_patching();
    int antikill = install_antikill_seccomp();

    if (patched > 0 || antikill) {
        KX_LOGI("svc killer: active (patched=%d, antikill=%d)", patched, antikill);
        return 1;
    }

    KX_LOGW("svc killer: all methods failed");
    return 0;
}

int kx_rescan_svc_sites(void) {
    pthread_mutex_lock(&kx_patch_lock);
    int newly = do_svc_patching();
    pthread_mutex_unlock(&kx_patch_lock);
    if (newly > 0)
        KX_LOGI("svc rescan: patched %d new sites from late-loaded libs", newly);
    return newly;
}

JNIEXPORT void JNICALL
Java_com_killerx_ApkRedirector_nativeRescanSvcSites(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    kx_rescan_svc_sites();
}

#else // not arm64

int kx_install_svc_killer(void) {
    KX_LOGW("svc killer only implemented for arm64");
    return 0;
}

int kx_rescan_svc_sites(void) {
    return 0;
}

#endif

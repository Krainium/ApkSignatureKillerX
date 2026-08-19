// PLT/GOT redirect of the open() family + advanced bypass hooks.
//
// Built on ByteHook (ByteDance). This is the modern replacement for the
// iqiyi xHook layer in the original ApkSignatureKillerEx.
//
// LAYERS:
//  1. open/openat redirect (base) - any libc open of our apk -> origin.apk
//  2. /proc/self/maps filter - hide our libraries from detection scans
//  3. exit/kill interception - prevent RASP from terminating the process
//  4. dlopen interception - detect and neutralize PairIP/RASP .so loads
//  5. fstat/statx redirect - spoof file size/inode for our apk
//  6. read() filter for /proc/self/maps fd - line-level filtering
//  7. RegisterNatives interception - catch PairIP executeVM registration

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <ucontext.h>
#include <dirent.h>

#include "bytehook.h"
#include "killerx.h"

const char *kx_apk_path = NULL;
const char *kx_rep_path = NULL;

// Maps filter patterns (set from Java)
const char **kx_maps_filter = NULL;
int kx_maps_filter_count = 0;

// Track fds opened on sensitive /proc files for read() filtering
#define KX_PROC_MAPS      1
#define KX_PROC_MOUNTINFO  2
#define KX_PROC_ENVIRON    3
#define KX_PROC_STATUS     4

#define MAX_TRACKED_FDS 32
static struct { int fd; int type; } kx_tracked_fds[MAX_TRACKED_FDS];
static int kx_tracked_count = 0;
static pthread_mutex_t kx_tracked_lock = PTHREAD_MUTEX_INITIALIZER;

// Original apk stat cache (for fstat spoof)
static struct stat kx_origin_stat;
static int kx_origin_stat_valid = 0;
volatile int kx_redirect_active = 0;

// ─── PATH REDIRECT ─────────────────────────────────────────────────────

static inline int ends_with_base_apk(const char *s) {
    if (!s) return 0;
    size_t len = strlen(s);
    return len >= 9 && strcmp(s + len - 9, "/base.apk") == 0;
}

static inline const char *redirect(const char *pathname) {
    if (!kx_redirect_active || !pathname || !kx_rep_path) return pathname;
    if (kx_apk_path) {
        if (strcmp(pathname, kx_apk_path) == 0) {
            KX_LOGI("redirect: %s -> %s", pathname, kx_rep_path);
            return kx_rep_path;
        }
    } else {
        if (strstr(pathname, "/data/app/") && ends_with_base_apk(pathname)) {
            KX_LOGI("redirect (auto): %s -> %s", pathname, kx_rep_path);
            return kx_rep_path;
        }
    }
    return pathname;
}

static inline int is_maps_path(const char *path) {
    if (!path) return 0;
    return strcmp(path, "/proc/self/maps") == 0 ||
           strcmp(path, "/proc/thread-self/maps") == 0;
}

static inline int is_proc_maps(const char *path) {
    if (!path) return 0;
    if (is_maps_path(path)) return 1;
    // Also match /proc/<pid>/maps
    if (strncmp(path, "/proc/", 6) == 0) {
        const char *rest = path + 6;
        while (*rest >= '0' && *rest <= '9') rest++;
        if (strcmp(rest, "/maps") == 0) return 1;
    }
    return 0;
}

static int classify_proc_path(const char *path) {
    if (!path) return 0;
    if (is_proc_maps(path)) return KX_PROC_MAPS;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    const char *rest = path + 6;
    if (strncmp(rest, "self/", 5) == 0) rest += 5;
    else if (strncmp(rest, "thread-self/", 12) == 0) rest += 12;
    else {
        while (*rest >= '0' && *rest <= '9') rest++;
        if (*rest == '/') rest++;
    }
    if (strcmp(rest, "mountinfo") == 0) return KX_PROC_MOUNTINFO;
    if (strcmp(rest, "environ") == 0) return KX_PROC_ENVIRON;
    if (strcmp(rest, "status") == 0) return KX_PROC_STATUS;
    return 0;
}

static void track_proc_fd(int fd, int type) {
    if (fd < 0 || type == 0) return;
    pthread_mutex_lock(&kx_tracked_lock);
    if (kx_tracked_count < MAX_TRACKED_FDS) {
        kx_tracked_fds[kx_tracked_count].fd = fd;
        kx_tracked_fds[kx_tracked_count].type = type;
        kx_tracked_count++;
    }
    pthread_mutex_unlock(&kx_tracked_lock);
}

static int get_proc_fd_type(int fd) {
    if (fd < 0) return 0;
    pthread_mutex_lock(&kx_tracked_lock);
    for (int i = 0; i < kx_tracked_count; i++) {
        if (kx_tracked_fds[i].fd == fd) {
            int t = kx_tracked_fds[i].type;
            pthread_mutex_unlock(&kx_tracked_lock);
            return t;
        }
    }
    pthread_mutex_unlock(&kx_tracked_lock);
    return 0;
}

static int should_filter_line(const char *line) {
    if (!kx_maps_filter || kx_maps_filter_count == 0) return 0;
    for (int i = 0; i < kx_maps_filter_count; i++) {
        if (strstr(line, kx_maps_filter[i]) != NULL) return 1;
    }
    return 0;
}

// ─── OPEN HOOKS ─────────────────────────────────────────────────────────

typedef int (*open_t)(const char *, int, mode_t);
typedef int (*openat_t)(int, const char *, int, mode_t);

static int proxy_open(const char *pathname, int flags, mode_t mode) {
    const char *target = redirect(pathname);
    int fd = BYTEHOOK_CALL_PREV(proxy_open, open_t, target, flags, mode);
    int ptype = classify_proc_path(pathname);
    if (ptype && fd >= 0) track_proc_fd(fd, ptype);
    BYTEHOOK_POP_STACK();
    return fd;
}

static int proxy_open64(const char *pathname, int flags, mode_t mode) {
    const char *target = redirect(pathname);
    int fd = BYTEHOOK_CALL_PREV(proxy_open64, open_t, target, flags, mode);
    int ptype = classify_proc_path(pathname);
    if (ptype && fd >= 0) track_proc_fd(fd, ptype);
    BYTEHOOK_POP_STACK();
    return fd;
}

static int proxy_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    const char *target = redirect(pathname);
    int fd = BYTEHOOK_CALL_PREV(proxy_openat, openat_t, dirfd, target, flags, mode);
    int ptype = classify_proc_path(pathname);
    if (ptype && fd >= 0) track_proc_fd(fd, ptype);
    BYTEHOOK_POP_STACK();
    return fd;
}

static int proxy_openat64(int dirfd, const char *pathname, int flags, mode_t mode) {
    const char *target = redirect(pathname);
    int fd = BYTEHOOK_CALL_PREV(proxy_openat64, openat_t, dirfd, target, flags, mode);
    int ptype = classify_proc_path(pathname);
    if (ptype && fd >= 0) track_proc_fd(fd, ptype);
    BYTEHOOK_POP_STACK();
    return fd;
}

// ─── READ HOOK (maps filtering) ─────────────────────────────────────────

typedef ssize_t (*read_t)(int, void *, size_t);

static ssize_t filter_lines(char *buf, ssize_t n,
                            int (*match)(const char *)) {
    char *src = buf, *dst = buf, *end = buf + n;
    while (src < end) {
        char *nl = memchr(src, '\n', end - src);
        size_t len = nl ? (size_t)(nl - src + 1) : (size_t)(end - src);
        char saved = src[len];
        src[len] = '\0';
        int drop = match(src);
        src[len] = saved;
        if (!drop) {
            if (dst != src) memmove(dst, src, len);
            dst += len;
        }
        src += len;
    }
    return (ssize_t)(dst - buf);
}

static int match_maps(const char *line) {
    return should_filter_line(line);
}

static int match_mountinfo(const char *line) {
    return strstr(line, "origin.apk") != NULL ||
           strstr(line, "killerx") != NULL ||
           (strstr(line, "/data/app/") && strstr(line, "base.apk") &&
            strstr(line, "/data/local/tmp/"));
}

static int match_status_seccomp(const char *line) {
    return strncmp(line, "Seccomp:", 8) == 0 ||
           strncmp(line, "Seccomp_filters:", 16) == 0;
}

static ssize_t filter_environ(char *buf, ssize_t n) {
    char *src = buf, *dst = buf, *end = buf + n;
    while (src < end) {
        size_t len = strnlen(src, end - src);
        int has_nul = (src + len < end);
        size_t entry_len = len + (has_nul ? 1 : 0);
        int drop = (strncmp(src, "LD_PRELOAD=", 11) == 0 ||
                    strncmp(src, "LD_LIBRARY_PATH=", 16) == 0 ||
                    strstr(src, "killerx") != NULL);
        if (!drop) {
            if (dst != src) memmove(dst, src, entry_len);
            dst += entry_len;
        }
        src += entry_len;
    }
    return (ssize_t)(dst - buf);
}

static ssize_t filter_status(char *buf, ssize_t n) {
    char *src = buf, *dst = buf, *end = buf + n;
    while (src < end) {
        char *nl = memchr(src, '\n', end - src);
        size_t len = nl ? (size_t)(nl - src + 1) : (size_t)(end - src);
        if (match_status_seccomp(src)) {
            const char *fake = (len > 10 && src[8] == '_') ?
                "Seccomp_filters:\t0\n" : "Seccomp:\t0\n";
            size_t flen = strlen(fake);
            memmove(dst, fake, flen);
            dst += flen;
        } else {
            if (dst != src) memmove(dst, src, len);
            dst += len;
        }
        src += len;
    }
    return (ssize_t)(dst - buf);
}

static ssize_t proxy_read(int fd, void *buf, size_t count) {
    ssize_t n = BYTEHOOK_CALL_PREV(proxy_read, read_t, fd, buf, count);
    BYTEHOOK_POP_STACK();

    if (n <= 0) return n;

    int ptype = get_proc_fd_type(fd);
    if (!ptype) return n;

    switch (ptype) {
    case KX_PROC_MAPS:
        if (kx_maps_filter_count > 0)
            return filter_lines((char *)buf, n, match_maps);
        break;
    case KX_PROC_MOUNTINFO:
        return filter_lines((char *)buf, n, match_mountinfo);
    case KX_PROC_ENVIRON:
        return filter_environ((char *)buf, n);
    case KX_PROC_STATUS:
        return filter_status((char *)buf, n);
    }
    return n;
}

// ─── EXIT/KILL HOOKS (RASP anti-termination) ─────────────────────────────

typedef void (*exit_t)(int);
typedef int (*kill_t)(pid_t, int);

volatile int kx_rasp_hooks_active = 0;

static int is_app_process(void) {
    char buf[256];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return strstr(buf, "app_process") != NULL || strstr(buf, ".unitviptv") != NULL;
}

static void proxy_exit(int status) {
    if (kx_rasp_hooks_active && is_app_process()) {
        KX_LOGW("blocked exit(%d) from RASP detection, suspending thread", status);
        BYTEHOOK_POP_STACK();
        for (;;) pause();
    }
    BYTEHOOK_CALL_PREV(proxy_exit, exit_t, status);
    BYTEHOOK_POP_STACK();
}

static void proxy__exit(int status) {
    if (kx_rasp_hooks_active && is_app_process()) {
        KX_LOGW("blocked _exit(%d) from RASP detection, suspending thread", status);
        BYTEHOOK_POP_STACK();
        for (;;) pause();
    }
    BYTEHOOK_CALL_PREV(proxy__exit, exit_t, status);
    BYTEHOOK_POP_STACK();
}

static int proxy_kill(pid_t pid, int sig) {
    if (kx_rasp_hooks_active && pid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
        KX_LOGW("blocked kill(self, %d) from RASP detection", sig);
        BYTEHOOK_POP_STACK();
        return 0;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_kill, kill_t, pid, sig);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── ABORT HOOK ─────────────────────────────────────────────────────────

typedef void (*abort_t)(void);

static void proxy_abort(void) {
    if (kx_rasp_hooks_active && is_app_process()) {
        KX_LOGW("blocked abort() from RASP detection, suspending");
        BYTEHOOK_POP_STACK();
        for (;;) pause();
    }
    BYTEHOOK_CALL_PREV(proxy_abort, abort_t);
    BYTEHOOK_POP_STACK();
}

// ─── RAISE / TGKILL / PTHREAD_KILL HOOKS ────────────────────────────────

typedef int (*raise_t)(int);
typedef int (*tgkill_t)(int, int, int);
typedef int (*pthread_kill_t)(pthread_t, int);

static int proxy_raise(int sig) {
    if (kx_rasp_hooks_active && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGSYS)) {
        KX_LOGW("blocked raise(%d) from RASP detection", sig);
        BYTEHOOK_POP_STACK();
        return 0;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_raise, raise_t, sig);
    BYTEHOOK_POP_STACK();
    return r;
}

static int proxy_tgkill(int tgid, int tid, int sig) {
    if (kx_rasp_hooks_active && tgid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
        KX_LOGW("blocked tgkill(%d, %d, %d) from RASP detection", tgid, tid, sig);
        BYTEHOOK_POP_STACK();
        return 0;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_tgkill, tgkill_t, tgid, tid, sig);
    BYTEHOOK_POP_STACK();
    return r;
}

static int proxy_pthread_kill(pthread_t thread, int sig) {
    if (kx_rasp_hooks_active && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
        KX_LOGW("blocked pthread_kill(sig=%d) from RASP detection", sig);
        BYTEHOOK_POP_STACK();
        return 0;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_pthread_kill, pthread_kill_t, thread, sig);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── SYSCALL() HOOK (catches arbitrary syscall via libc wrapper) ──────────

typedef long (*syscall_t)(long, ...);

static long proxy_syscall(long nr, ...) {
    va_list args;
    va_start(args, nr);
    long a0 = va_arg(args, long);
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    va_end(args);

    if (kx_rasp_hooks_active) {
        if (nr == __NR_kill) {
            pid_t pid = (pid_t)a0;
            int sig = (int)a1;
            if (pid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
                KX_LOGW("blocked syscall(kill, %d, %d)", pid, sig);
                BYTEHOOK_POP_STACK();
                return 0;
            }
        }
        if (nr == __NR_tgkill) {
            int tgid = (int)a0;
            int sig = (int)a2;
            if (tgid == getpid() && (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT)) {
                KX_LOGW("blocked syscall(tgkill, %d, sig=%d)", tgid, sig);
                BYTEHOOK_POP_STACK();
                return 0;
            }
        }
        if ((nr == __NR_exit || nr == __NR_exit_group) && is_app_process()) {
            KX_LOGW("blocked syscall(exit/exit_group %ld, %ld), suspending", nr, a0);
            BYTEHOOK_POP_STACK();
            for (;;) pause();
        }
    }

    long r = BYTEHOOK_CALL_PREV(proxy_syscall, syscall_t, nr, a0, a1, a2, a3, a4, a5);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── MMAP HOOKS (redirect APK mmap reads to origin.apk) ─────────────────

typedef void *(*mmap_t)(void *, size_t, int, int, int, off_t);

static int open_origin_fd(void) {
    if (!kx_rep_path) return -1;
    return open(kx_rep_path, O_RDONLY);
}

static int fd_is_apk(int fd) {
    if (!kx_redirect_active || fd < 0) return 0;
    char link[64], path[512];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = '\0';
    if (kx_apk_path)
        return strcmp(path, kx_apk_path) == 0;
    return strstr(path, "/data/app/") && ends_with_base_apk(path);
}

static void *proxy_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (fd_is_apk(fd)) {
        int origin_fd = open_origin_fd();
        if (origin_fd >= 0) {
            KX_LOGI("mmap redirect: fd %d -> origin.apk", fd);
            void *r = BYTEHOOK_CALL_PREV(proxy_mmap, mmap_t, addr, length, prot, flags, origin_fd, offset);
            close(origin_fd);
            BYTEHOOK_POP_STACK();
            return r;
        }
    }
    void *r = BYTEHOOK_CALL_PREV(proxy_mmap, mmap_t, addr, length, prot, flags, fd, offset);
    BYTEHOOK_POP_STACK();
    return r;
}

static void *proxy_mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (fd_is_apk(fd)) {
        int origin_fd = open_origin_fd();
        if (origin_fd >= 0) {
            KX_LOGI("mmap64 redirect: fd %d -> origin.apk", fd);
            void *r = BYTEHOOK_CALL_PREV(proxy_mmap64, mmap_t, addr, length, prot, flags, origin_fd, offset);
            close(origin_fd);
            BYTEHOOK_POP_STACK();
            return r;
        }
    }
    void *r = BYTEHOOK_CALL_PREV(proxy_mmap64, mmap_t, addr, length, prot, flags, fd, offset);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── DLOPEN HOOK (PairIP/RASP .so detection) ─────────────────────────────

typedef void *(*dlopen_t)(const char *, int);

static JavaVM *kx_jvm = NULL;

static void reinstall_sigtrap_handler(void);
static volatile int kx_openat2_trap_armed = 0;
static void hijack_existing_apk_fds(void);
static void patch_existing_apk_mmaps(void);

static volatile int kx_bind_mount_mode = 0;

static void maybe_arm_openat2_trap(const char *filename) {
    if (!filename) return;
    if (strstr(filename, "libexec") || strstr(filename, "shell") ||
        strstr(filename, "s.h.e.l.l") || strstr(filename, "ijiami")) {
        if (!kx_redirect_active) {
            kx_redirect_active = 1;
            KX_LOGI("packer native lib detected (%s), APK redirect NOW ACTIVE", filename);
        }
        if (kx_rep_path && !kx_openat2_trap_armed && !kx_bind_mount_mode) {
            KX_LOGI("arming openat2 seccomp trap for SVC-level redirect");
            if (kx_install_svc_killer())
                kx_openat2_trap_armed = 1;
            if (kx_install_seccomp_redirect())
                KX_LOGI("seccomp openat redirect armed");
            hijack_existing_apk_fds();
            patch_existing_apk_mmaps();
        }
    }
}

static void *proxy_dlopen(const char *filename, int flags) {
    void *handle = BYTEHOOK_CALL_PREV(proxy_dlopen, dlopen_t, filename, flags);
    BYTEHOOK_POP_STACK();

    reinstall_sigtrap_handler();
    kx_rescan_svc_sites();
    maybe_arm_openat2_trap(filename);

    if (filename) {
        // Detect PairIP
        if (strstr(filename, "pairipcore") || strstr(filename, "pairip")) {
            KX_LOGI("PairIP detected: %s", filename);
            if (kx_jvm) {
                JNIEnv *env = NULL;
                if ((*kx_jvm)->GetEnv(kx_jvm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
                    jclass cls = (*env)->FindClass(env, "com/killerx/PairIPNeutralizer");
                    if (cls) {
                        jmethodID mid = (*env)->GetStaticMethodID(env, cls, "onPairIPDetected", "(Ljava/lang/String;)V");
                        if (mid) {
                            jstring path = (*env)->NewStringUTF(env, filename);
                            (*env)->CallStaticVoidMethod(env, cls, mid, path);
                            (*env)->DeleteLocalRef(env, path);
                        }
                        (*env)->DeleteLocalRef(env, cls);
                    }
                }
            }
        }

        // Detect common RASP libraries
        if (strstr(filename, "talsec") || strstr(filename, "yinko") ||
            strstr(filename, "rasp") || strstr(filename, "dexguard")) {
            KX_LOGI("RASP library detected: %s", filename);
        }
    }
    return handle;
}

// ─── ANDROID_DLOPEN_EXT HOOK (System.load uses this, not dlopen) ─────────

typedef void *(*android_dlopen_ext_t)(const char *, int, const void *);

static void *proxy_android_dlopen_ext(const char *filename, int flags, const void *info) {
    void *handle = BYTEHOOK_CALL_PREV(proxy_android_dlopen_ext, android_dlopen_ext_t, filename, flags, info);
    BYTEHOOK_POP_STACK();

    reinstall_sigtrap_handler();
    kx_rescan_svc_sites();
    maybe_arm_openat2_trap(filename);

    if (filename) {
        if (strstr(filename, "pairipcore") || strstr(filename, "pairip"))
            KX_LOGI("PairIP detected: %s", filename);
        if (strstr(filename, "talsec") || strstr(filename, "yinko") ||
            strstr(filename, "rasp") || strstr(filename, "dexguard"))
            KX_LOGI("RASP library detected: %s", filename);
    }
    return handle;
}

// ─── PROPERTY HOOK (hide wrap.* debug property) ─────────────────────────

typedef int (*prop_get_t)(const char *, char *);

static int proxy___system_property_get(const char *name, char *value) {
    int r = BYTEHOOK_CALL_PREV(proxy___system_property_get, prop_get_t, name, value);
    BYTEHOOK_POP_STACK();
    if (r > 0 && name && strncmp(name, "wrap.", 5) == 0) {
        value[0] = '\0';
        return 0;
    }
    return r;
}

// ─── CLOSE HOOK (untrack proc fds) ──────────────────────────────────────

typedef int (*close_t)(int);

static int proxy_close(int fd) {
    if (fd >= 0) {
        pthread_mutex_lock(&kx_tracked_lock);
        for (int i = 0; i < kx_tracked_count; i++) {
            if (kx_tracked_fds[i].fd == fd) {
                kx_tracked_fds[i] = kx_tracked_fds[--kx_tracked_count];
                break;
            }
        }
        pthread_mutex_unlock(&kx_tracked_lock);
    }
    int r = BYTEHOOK_CALL_PREV(proxy_close, close_t, fd);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── ARTIFACT HIDING (stat/access/readdir) ──────────────────────────────

static int is_killerx_artifact(const char *path) {
    if (!path || strncmp(path, "/data/local/tmp/", 16) != 0) return 0;
    const char *name = path + 16;
    if (strcmp(name, "origin.apk") == 0) return 1;
    if (strcmp(name, "libkillerx.so") == 0) return 1;
    if (strcmp(name, "libbytehook.so") == 0) return 1;
    if (strcmp(name, "wrap.sh") == 0) return 1;
    if (strncmp(name, ".killerx_", 9) == 0) return 1;
    if (strncmp(name, ".kx_", 4) == 0) return 1;
    if (strncmp(name, "wrap_", 5) == 0) return 1;
    return 0;
}

static int is_artifact_name(const char *name) {
    if (!name) return 0;
    if (strcmp(name, "origin.apk") == 0) return 1;
    if (strcmp(name, "libkillerx.so") == 0) return 1;
    if (strcmp(name, "libbytehook.so") == 0) return 1;
    if (strcmp(name, "wrap.sh") == 0) return 1;
    if (strncmp(name, ".killerx_", 9) == 0) return 1;
    if (strncmp(name, ".kx_", 4) == 0) return 1;
    if (strncmp(name, "wrap_", 5) == 0) return 1;
    return 0;
}

typedef int (*stat_t)(const char *, struct stat *);
typedef int (*access_t)(const char *, int);

static int proxy_stat(const char *path, struct stat *buf) {
    if (is_killerx_artifact(path)) {
        BYTEHOOK_POP_STACK();
        errno = ENOENT;
        return -1;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_stat, stat_t, path, buf);
    BYTEHOOK_POP_STACK();
    return r;
}

static int proxy_lstat(const char *path, struct stat *buf) {
    if (is_killerx_artifact(path)) {
        BYTEHOOK_POP_STACK();
        errno = ENOENT;
        return -1;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_lstat, stat_t, path, buf);
    BYTEHOOK_POP_STACK();
    return r;
}

static int proxy_access(const char *path, int mode) {
    if (is_killerx_artifact(path)) {
        BYTEHOOK_POP_STACK();
        errno = ENOENT;
        return -1;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_access, access_t, path, mode);
    BYTEHOOK_POP_STACK();
    return r;
}

// Readdir filtering for /data/local/tmp/
typedef DIR *(*opendir_t)(const char *);
typedef struct dirent *(*readdir_t)(DIR *);
typedef int (*closedir_t)(DIR *);

#define MAX_HIDDEN_DIRS 4
static DIR *kx_hidden_dirs[MAX_HIDDEN_DIRS];
static int kx_hidden_dir_count = 0;

static int is_hidden_dir(DIR *d) {
    for (int i = 0; i < kx_hidden_dir_count; i++)
        if (kx_hidden_dirs[i] == d) return 1;
    return 0;
}

static DIR *proxy_opendir(const char *name) {
    DIR *d = BYTEHOOK_CALL_PREV(proxy_opendir, opendir_t, name);
    BYTEHOOK_POP_STACK();
    if (d && name && strcmp(name, "/data/local/tmp") == 0 &&
        kx_hidden_dir_count < MAX_HIDDEN_DIRS)
        kx_hidden_dirs[kx_hidden_dir_count++] = d;
    return d;
}

static struct dirent *proxy_readdir(DIR *d) {
    struct dirent *ent;
    do {
        ent = BYTEHOOK_CALL_PREV(proxy_readdir, readdir_t, d);
    } while (ent && is_hidden_dir(d) && is_artifact_name(ent->d_name));
    BYTEHOOK_POP_STACK();
    return ent;
}

static int proxy_closedir(DIR *d) {
    for (int i = 0; i < kx_hidden_dir_count; i++) {
        if (kx_hidden_dirs[i] == d) {
            kx_hidden_dirs[i] = kx_hidden_dirs[--kx_hidden_dir_count];
            break;
        }
    }
    int r = BYTEHOOK_CALL_PREV(proxy_closedir, closedir_t, d);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── INSTALL FUNCTIONS ──────────────────────────────────────────────────

static void install_plt(void) {
    bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    bytehook_hook_all(NULL, "openat64", (void *) proxy_openat64, NULL, NULL);
    bytehook_hook_all(NULL, "openat",   (void *) proxy_openat,   NULL, NULL);
    bytehook_hook_all(NULL, "open64",   (void *) proxy_open64,   NULL, NULL);
    bytehook_hook_all(NULL, "open",     (void *) proxy_open,     NULL, NULL);
    bytehook_hook_all(NULL, "read",     (void *) proxy_read,     NULL, NULL);
    bytehook_hook_all(NULL, "close",    (void *) proxy_close,    NULL, NULL);
    bytehook_hook_all(NULL, "dlopen",   (void *) proxy_dlopen,   NULL, NULL);
    bytehook_hook_all(NULL, "android_dlopen_ext",            (void *) proxy_android_dlopen_ext, NULL, NULL);
    bytehook_hook_all(NULL, "__loader_android_dlopen_ext",   (void *) proxy_android_dlopen_ext, NULL, NULL);
    bytehook_hook_all(NULL, "raise",        (void *) proxy_raise,        NULL, NULL);
    bytehook_hook_all(NULL, "tgkill",       (void *) proxy_tgkill,       NULL, NULL);
    bytehook_hook_all(NULL, "pthread_kill", (void *) proxy_pthread_kill, NULL, NULL);
    bytehook_hook_all(NULL, "syscall",      (void *) proxy_syscall,      NULL, NULL);
    bytehook_hook_all(NULL, "mmap",        (void *) proxy_mmap,         NULL, NULL);
    bytehook_hook_all(NULL, "mmap64",      (void *) proxy_mmap64,       NULL, NULL);
    bytehook_hook_all(NULL, "__system_property_get", (void *) proxy___system_property_get, NULL, NULL);
    bytehook_hook_all(NULL, "stat",     (void *) proxy_stat,     NULL, NULL);
    bytehook_hook_all(NULL, "lstat",    (void *) proxy_lstat,    NULL, NULL);
    bytehook_hook_all(NULL, "access",   (void *) proxy_access,   NULL, NULL);
    bytehook_hook_all(NULL, "opendir",  (void *) proxy_opendir,  NULL, NULL);
    bytehook_hook_all(NULL, "readdir",  (void *) proxy_readdir,  NULL, NULL);
    bytehook_hook_all(NULL, "closedir", (void *) proxy_closedir, NULL, NULL);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    kx_jvm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_killerx_ApkRedirector_nativeInstallPltRedirect(
        JNIEnv *env, jobject thiz, jstring apkPath, jstring originPath) {
    (void) thiz;
    kx_apk_path = (*env)->GetStringUTFChars(env, apkPath, 0);
    kx_rep_path = (*env)->GetStringUTFChars(env, originPath, 0);
    KX_LOGI("plt redirect %s -> %s", kx_apk_path, kx_rep_path);

    // Cache origin stat for fstat spoofing
    if (stat(kx_rep_path, &kx_origin_stat) == 0) {
        kx_origin_stat_valid = 1;
    }

    install_plt();
}

JNIEXPORT jboolean JNICALL
Java_com_killerx_ApkRedirector_nativeInstallSyscallTrap(
        JNIEnv *env, jobject thiz, jstring apkPath, jstring originPath) {
    (void) thiz;
    if (kx_apk_path == NULL) kx_apk_path = (*env)->GetStringUTFChars(env, apkPath, 0);
    if (kx_rep_path == NULL) kx_rep_path = (*env)->GetStringUTFChars(env, originPath, 0);
    return kx_install_svc_killer() ? JNI_TRUE : JNI_FALSE;
}

// ─── FD HIJACK (replace pre-existing fds to base.apk with origin.apk) ───

static int path_is_target_apk(const char *path) {
    if (kx_apk_path)
        return strcmp(path, kx_apk_path) == 0;
    return strstr(path, "/data/app/") && ends_with_base_apk(path);
}

static void hijack_existing_apk_fds(void) {
    if (!kx_rep_path) return;

    char fddir[64];
    snprintf(fddir, sizeof(fddir), "/proc/self/fd");
    DIR *d = opendir(fddir);
    if (!d) return;

    int hijacked = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        int fd = atoi(ent->d_name);
        if (fd < 3) continue;

        char link[64], path[512];
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(link, path, sizeof(path) - 1);
        if (n <= 0) continue;
        path[n] = '\0';

        if (!path_is_target_apk(path)) continue;

        off_t pos = lseek(fd, 0, SEEK_CUR);
        int origin_fd = open(kx_rep_path, O_RDONLY);
        if (origin_fd < 0) continue;

        if (dup2(origin_fd, fd) >= 0) {
            if (pos > 0) lseek(fd, pos, SEEK_SET);
            hijacked++;
            KX_LOGI("fd hijack: fd %d -> origin.apk (was at offset %ld)", fd, (long)pos);
        }
        close(origin_fd);
    }
    closedir(d);
    if (hijacked > 0)
        KX_LOGI("fd hijack: replaced %d fds to base.apk", hijacked);
    else
        KX_LOGI("fd hijack: no pre-existing fds to base.apk found");
}

// ─── MMAP PATCHING (replace pre-existing APK mmap with origin.apk) ──────

static void patch_existing_apk_mmaps(void) {
    if (!kx_rep_path) return;

    int origin_fd = open(kx_rep_path, O_RDONLY);
    if (origin_fd < 0) {
        KX_LOGW("mmap patch: can't open origin.apk");
        return;
    }

    struct stat origin_st;
    if (fstat(origin_fd, &origin_st) != 0) {
        close(origin_fd);
        return;
    }

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        KX_LOGW("mmap patch: can't open /proc/self/maps");
        close(origin_fd);
        return;
    }

    char line[512];
    int patched = 0, checked = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, "/data/app/") || !strstr(line, "base.apk")) continue;
        checked++;
        KX_LOGI("mmap patch: found mapping: %s", line);

        unsigned long ul_start, ul_end, ul_offset;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s %lx", &ul_start, &ul_end, perms, &ul_offset) != 4) continue;

        size_t len = ul_end - ul_start;
        if (ul_offset + len > (size_t)origin_st.st_size) continue;

        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;

        void *m = mmap((void *)(uintptr_t)ul_start, len, prot,
                        MAP_PRIVATE | MAP_FIXED, origin_fd, (off_t)ul_offset);
        if (m == MAP_FAILED) {
            KX_LOGW("mmap patch: fail at offset %lx: %s", ul_offset, strerror(errno));
        } else {
            patched++;
        }
    }

    fclose(maps);
    close(origin_fd);
    if (patched > 0)
        KX_LOGI("mmap patch: replaced %d/%d base.apk regions with origin.apk", patched, checked);
    else
        KX_LOGI("mmap patch: found %d base.apk regions, patched 0", checked);
}

// ─── SIGTRAP HANDLER (chain with packer's VMP handler) ──────────────────

static struct sigaction kx_orig_sigtrap;
static volatile int kx_sigtrap_skip_next = 0;

static void sigtrap_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
#if defined(__aarch64__)
    uintptr_t pc = ctx->uc_mcontext.pc;
    uint32_t insn = *(uint32_t *)pc;
    if ((insn & 0xFFE0001F) == 0xD4200000) {
        uint32_t brk_imm = (insn >> 5) & 0xFFFF;
        if (brk_imm <= 1) {
            KX_LOGW("SIGTRAP: absorbed anti-tamper BRK #%u at pc=%lx", brk_imm, (unsigned long)pc);
            ctx->uc_mcontext.regs[0] = 0;
            ctx->uc_mcontext.pc = pc + 4;
            return;
        }
    }
#elif defined(__arm__)
    uintptr_t pc = ctx->uc_mcontext.arm_pc;
    uint32_t insn = *(uint32_t *)pc;
    if ((insn & 0xFFF000F0) == 0xE1200070) {
        ctx->uc_mcontext.arm_r0 = 0;
        ctx->uc_mcontext.arm_pc = pc + 4;
        return;
    }
#endif
    if (kx_orig_sigtrap.sa_flags & SA_SIGINFO &&
        kx_orig_sigtrap.sa_sigaction != NULL) {
        kx_orig_sigtrap.sa_sigaction(sig, info, ucontext);
    } else if (kx_orig_sigtrap.sa_handler != SIG_DFL &&
               kx_orig_sigtrap.sa_handler != SIG_IGN &&
               kx_orig_sigtrap.sa_handler != NULL) {
        kx_orig_sigtrap.sa_handler(sig);
    } else {
#if defined(__aarch64__)
        KX_LOGW("SIGTRAP: no chain target, skipping BRK at pc=%lx", (unsigned long)ctx->uc_mcontext.pc);
        ctx->uc_mcontext.pc += 4;
#elif defined(__arm__)
        ctx->uc_mcontext.arm_pc += 4;
#endif
    }
}

static struct sigaction kx_orig_sigsegv;

static volatile int kx_crash_count = 0;
#define KX_MAX_CRASHES 10000

static void vmp_crash_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
#if defined(__aarch64__)
    if (kx_redirect_active) {
        int cnt = ++kx_crash_count;
        if (cnt > KX_MAX_CRASHES) {
            signal(sig, SIG_DFL);
            return;
        }
        uintptr_t fault = (uintptr_t)info->si_addr;
        uintptr_t pc = ctx->uc_mcontext.pc;
        if (cnt <= 5 || (cnt % 500 == 0))
            KX_LOGW("sig%d: absorbed #%d pc=%lx fault=%lx code=%d",
                     sig, cnt, (unsigned long)pc, (unsigned long)fault, info->si_code);

        if (sig == SIGSEGV && info->si_code == SEGV_ACCERR) {
            uintptr_t page = fault & ~0xFFFUL;
            mprotect((void *)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
        } else {
            ctx->uc_mcontext.regs[0] = 0;
            ctx->uc_mcontext.pc = pc + 4;
        }
        return;
    }
#endif
    if (sig == SIGSEGV) {
        if (kx_orig_sigsegv.sa_flags & SA_SIGINFO && kx_orig_sigsegv.sa_sigaction)
            kx_orig_sigsegv.sa_sigaction(sig, info, ucontext);
        else if (kx_orig_sigsegv.sa_handler != SIG_DFL && kx_orig_sigsegv.sa_handler != SIG_IGN)
            kx_orig_sigsegv.sa_handler(sig);
    }
}

static void install_sigtrap_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, &kx_orig_sigtrap) == 0) {
        KX_LOGI("SIGTRAP chained handler installed");
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = vmp_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &kx_orig_sigsegv) == 0)
        KX_LOGI("SIGSEGV VMP crash absorber installed");
    if (sigaction(SIGBUS, &sa, NULL) == 0)
        KX_LOGI("SIGBUS VMP crash absorber installed");
    if (sigaction(SIGILL, &sa, NULL) == 0)
        KX_LOGI("SIGILL VMP crash absorber installed");
    if (sigaction(SIGFPE, &sa, NULL) == 0)
        KX_LOGI("SIGFPE VMP crash absorber installed");
}

static void reinstall_sigtrap_handler(void) {
    struct sigaction current;
    memset(&current, 0, sizeof(current));
    sigaction(SIGTRAP, NULL, &current);
    if (current.sa_sigaction == sigtrap_handler)
        return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, &kx_orig_sigtrap) == 0) {
        KX_LOGI("SIGTRAP handler re-installed, captured packer handler as chain target");
    }
}

// ─── SIGACTION HOOK (prevent packers from overriding our SIGTRAP) ────────

typedef int (*sigaction_t)(int, const struct sigaction *, struct sigaction *);

static int proxy_sigaction(int signum, const struct sigaction *act,
                           struct sigaction *oldact) {
    if ((signum == SIGSEGV || signum == SIGBUS ||
         signum == SIGILL  || signum == SIGFPE) && act != NULL) {
        if (signum == SIGSEGV) {
            if (act->sa_flags & SA_SIGINFO)
                kx_orig_sigsegv.sa_sigaction = act->sa_sigaction;
            else
                kx_orig_sigsegv.sa_handler = act->sa_handler;
            kx_orig_sigsegv.sa_flags = act->sa_flags;
        }
        KX_LOGI("sigaction hook: blocked sig%d override, keeping ours", signum);
        if (oldact) {
            struct sigaction ours;
            memset(&ours, 0, sizeof(ours));
            ours.sa_sigaction = vmp_crash_handler;
            ours.sa_flags = SA_SIGINFO | SA_NODEFER;
            *oldact = ours;
        }
        BYTEHOOK_POP_STACK();
        return 0;
    }
    if (signum == SIGTRAP && act != NULL) {
        // Save packer's handler as our chain target
        if (act->sa_flags & SA_SIGINFO) {
            kx_orig_sigtrap.sa_sigaction = act->sa_sigaction;
        } else {
            kx_orig_sigtrap.sa_handler = act->sa_handler;
        }
        kx_orig_sigtrap.sa_flags = act->sa_flags;
        kx_orig_sigtrap.sa_mask = act->sa_mask;
        KX_LOGI("sigaction hook: captured packer SIGTRAP handler, keeping ours");
        if (oldact) {
            struct sigaction ours;
            memset(&ours, 0, sizeof(ours));
            ours.sa_sigaction = sigtrap_handler;
            ours.sa_flags = SA_SIGINFO;
            *oldact = ours;
        }
        BYTEHOOK_POP_STACK();
        return 0;
    }
    int r = BYTEHOOK_CALL_PREV(proxy_sigaction, sigaction_t, signum, act, oldact);
    BYTEHOOK_POP_STACK();
    return r;
}

// ─── EARLY INIT (from AppComponentFactory, before Ijiami loads) ─────────

JNIEXPORT void JNICALL
Java_com_killerx_boot_KillerXFactory_nativeEarlyInit(
        JNIEnv *env, jclass clz, jstring apkPath, jstring originPath) {
    (void)clz;
    kx_apk_path = (*env)->GetStringUTFChars(env, apkPath, 0);
    kx_rep_path = (*env)->GetStringUTFChars(env, originPath, 0);
    kx_redirect_active = 1;
    KX_LOGI("early init %s -> %s", kx_apk_path, kx_rep_path);

    if (stat(kx_rep_path, &kx_origin_stat) == 0) {
        kx_origin_stat_valid = 1;
    }

    hijack_existing_apk_fds();
    patch_existing_apk_mmaps();
    install_sigtrap_handler();

    static const char *early_filter[] = {
        "libkillerx.so", "libbytehook.so", "libshadowhook.so",
        "KillerX", "killerx"
    };
    kx_maps_filter = early_filter;
    kx_maps_filter_count = 5;

    install_plt();
    bytehook_hook_all(NULL, "sigaction", (void *) proxy_sigaction, NULL, NULL);
    KX_LOGI("sigaction PLT hook installed");
    kx_install_svc_killer();

    kx_rasp_hooks_active = 1;
    bytehook_hook_all(NULL, "exit",         (void *) proxy_exit,         NULL, NULL);
    bytehook_hook_all(NULL, "_exit",        (void *) proxy__exit,        NULL, NULL);
    bytehook_hook_all(NULL, "kill",         (void *) proxy_kill,         NULL, NULL);
    bytehook_hook_all(NULL, "abort",        (void *) proxy_abort,        NULL, NULL);
    bytehook_hook_all(NULL, "raise",        (void *) proxy_raise,        NULL, NULL);
    bytehook_hook_all(NULL, "tgkill",       (void *) proxy_tgkill,       NULL, NULL);
    bytehook_hook_all(NULL, "pthread_kill", (void *) proxy_pthread_kill, NULL, NULL);
    bytehook_hook_all(NULL, "syscall",      (void *) proxy_syscall,      NULL, NULL);
    KX_LOGI("RASP full hooks active (exit/kill/raise/tgkill/syscall)");
}

// ─── RASP HOOKS ─────────────────────────────────────────────────────────

JNIEXPORT void JNICALL
Java_com_killerx_RASPKiller_nativeInstallRaspHooks(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    kx_rasp_hooks_active = 1;
    bytehook_hook_all(NULL, "exit",  (void *) proxy_exit,  NULL, NULL);
    bytehook_hook_all(NULL, "_exit", (void *) proxy__exit, NULL, NULL);
    bytehook_hook_all(NULL, "kill",  (void *) proxy_kill,  NULL, NULL);
    KX_LOGI("RASP exit/kill hooks installed");
}

// ─── PAIRIP HOOKS ───────────────────────────────────────────────────────

JNIEXPORT jboolean JNICALL
Java_com_killerx_PairIPNeutralizer_nativeInstallPairIPHooks(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    // dlopen hook is already installed in install_plt()
    // RegisterNatives interception happens at the JNI level
    KX_LOGI("PairIP hooks registered (dlopen + JNI monitoring)");
    return JNI_TRUE;
}

// ─── MAPS FILTER ────────────────────────────────────────────────────────

static volatile int kx_base_hooks_installed = 0;

static void ensure_base_hooks(void) {
    if (kx_base_hooks_installed) return;
    kx_base_hooks_installed = 1;
    bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    bytehook_hook_all(NULL, "read",     (void *) proxy_read,     NULL, NULL);
    bytehook_hook_all(NULL, "dlopen",   (void *) proxy_dlopen,   NULL, NULL);
    KX_LOGI("base hooks installed (read + dlopen)");
}

JNIEXPORT void JNICALL
Java_com_killerx_ProbeEvasion_nativeInstallMapsFilter(
        JNIEnv *env, jobject thiz, jobjectArray patterns) {
    (void)thiz;
    int count = (*env)->GetArrayLength(env, patterns);
    const char **filter = (const char **)calloc(count, sizeof(char *));
    for (int i = 0; i < count; i++) {
        jstring s = (jstring)(*env)->GetObjectArrayElement(env, patterns, i);
        filter[i] = (*env)->GetStringUTFChars(env, s, 0);
    }
    kx_maps_filter = filter;
    kx_maps_filter_count = count;

    // Ensure read()/open() hooks are installed even if ApkRedirector
    // was skipped (no origin.apk asset)
    ensure_base_hooks();

    // Also hook open so we can track maps fds
    bytehook_hook_all(NULL, "openat64", (void *) proxy_openat64, NULL, NULL);
    bytehook_hook_all(NULL, "openat",   (void *) proxy_openat,   NULL, NULL);
    bytehook_hook_all(NULL, "open64",   (void *) proxy_open64,   NULL, NULL);
    bytehook_hook_all(NULL, "open",     (void *) proxy_open,     NULL, NULL);

    KX_LOGI("maps filter installed: %d patterns (with open/read hooks)", count);
}

// ─── LD_PRELOAD AUTO-INIT ───────────────────────────────────────────────

__attribute__((constructor))
static void kx_preload_init(void) {
    int marker_fd = creat("/data/local/tmp/.kx_alive", 0666);
    if (marker_fd >= 0) close(marker_fd);

    const char *preload = getenv("LD_PRELOAD");
    int preload_mode = (preload && strstr(preload, "libkillerx"));

    struct stat st_origin;
    int origin_exists = (stat("/data/local/tmp/origin.apk", &st_origin) == 0);

    if (!preload_mode && !origin_exists)
        return;

    if (preload_mode)
        unsetenv("LD_PRELOAD");

    KX_LOGI("%s mode: auto-init", preload_mode ? "LD_PRELOAD" : "embedded");

    if (origin_exists) {
        kx_origin_stat = st_origin;
        kx_origin_stat_valid = 1;
        kx_rep_path = "/data/local/tmp/origin.apk";
        kx_redirect_active = 1;
        if (stat("/data/local/tmp/.killerx_bind_mount", &(struct stat){0}) == 0) {
            kx_bind_mount_mode = 1;
            KX_LOGI("bind mount mode: redirect active, skipping seccomp redirect");
        } else {
            KX_LOGI("redirect mode: redirect active, seccomp armed");
        }

        // Auto-detect kx_apk_path from /proc/self/maps
        FILE *mapf = fopen("/proc/self/maps", "r");
        if (mapf) {
            char mapline[512];
            while (fgets(mapline, sizeof(mapline), mapf)) {
                char *p = strstr(mapline, "/data/app/");
                if (p) {
                    char *apk = strstr(p, "/base.apk");
                    if (apk) {
                        size_t plen = (size_t)(apk + 9 - p);
                        char *detected = (char *)malloc(plen + 1);
                        memcpy(detected, p, plen);
                        detected[plen] = '\0';
                        kx_apk_path = detected;
                        KX_LOGI("auto-detected apk: %s", kx_apk_path);
                        break;
                    }
                }
            }
            fclose(mapf);
        }
    }

    install_sigtrap_handler();

    static const char *preload_filter[] = {
        "libkillerx.so", "libbytehook.so", "libshadowhook.so",
        "KillerX", "killerx"
    };
    kx_maps_filter = preload_filter;
    kx_maps_filter_count = 5;

    int level = 7;
    {
        int lf = open("/data/local/tmp/.killerx_level", O_RDONLY);
        if (lf >= 0) {
            char lb[8] = {0};
            read(lf, lb, sizeof(lb) - 1);
            close(lf);
            level = atoi(lb);
            if (level < 3) level = 3;
            if (level > 7) level = 7;
            KX_LOGI("debug feature level: %d", level);
        }
    }

    bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);

    if (level >= 4)
        install_plt();

    bytehook_hook_all(NULL, "sigaction", (void *) proxy_sigaction, NULL, NULL);

    if (level >= 5)
        kx_install_svc_killer();

    if (level >= 6) {
        kx_rasp_hooks_active = 1;
        bytehook_hook_all(NULL, "exit",         (void *) proxy_exit,         NULL, NULL);
        bytehook_hook_all(NULL, "_exit",        (void *) proxy__exit,        NULL, NULL);
        bytehook_hook_all(NULL, "kill",         (void *) proxy_kill,         NULL, NULL);
        bytehook_hook_all(NULL, "abort",        (void *) proxy_abort,        NULL, NULL);
        bytehook_hook_all(NULL, "raise",        (void *) proxy_raise,        NULL, NULL);
        bytehook_hook_all(NULL, "tgkill",       (void *) proxy_tgkill,       NULL, NULL);
        bytehook_hook_all(NULL, "pthread_kill", (void *) proxy_pthread_kill, NULL, NULL);
        bytehook_hook_all(NULL, "syscall",      (void *) proxy_syscall,      NULL, NULL);
    }

    KX_LOGI("LD_PRELOAD mode: all hooks active");
}

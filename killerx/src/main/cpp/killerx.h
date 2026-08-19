#ifndef KILLERX_H
#define KILLERX_H

#include <android/log.h>

#define KX_TAG "KillerX/native"
#define KX_LOGI(...) __android_log_print(ANDROID_LOG_INFO,  KX_TAG, __VA_ARGS__)
#define KX_LOGW(...) __android_log_print(ANDROID_LOG_WARN,  KX_TAG, __VA_ARGS__)
#define KX_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, KX_TAG, __VA_ARGS__)

// Shared redirect target, set once at install time. Read-only afterwards.
extern const char *kx_apk_path;   // our own base.apk
extern const char *kx_rep_path;   // the bundled original apk
extern volatile int kx_redirect_active;

// Legacy seccomp_trap.c functions now in svc_killer.c

// Implemented in svc_killer.c. SVC patching + antikill seccomp.
int kx_install_svc_killer(void);

// Seccomp redirect: traps openat/newfstatat, redirects base.apk reads to
// origin.apk via SIGSYS handler. Non-matching paths escape through openat2/statx.
int kx_install_seccomp_redirect(void);

// Central SVC handler (svc_killer.c). Used by trampoline and runtime methods.
long kx_handle_svc(long nr, long a0, long a1, long a2, long a3, long a4, long a5);

// Re-scan /proc/self/maps and patch SVC sites in newly-loaded .so files.
// Call from dlopen hook to cover late-loaded libraries.
int kx_rescan_svc_sites(void);

// RASP termination blocking flag — shared between killerx.c and svc_killer.c.
extern volatile int kx_rasp_hooks_active;

// Maps filter — shared between killerx.c and seccomp_trap.c.
extern const char **kx_maps_filter;
extern int kx_maps_filter_count;

#endif // KILLERX_H

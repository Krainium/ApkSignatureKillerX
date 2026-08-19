// Direct openat via inline `svc #0`, bypassing the libc PLT.
//
// This is the demo's anti-killer probe. A PLT/GOT hook (ByteHook / xHook) never
// sees this call because it never resolves an imported open symbol, so it reads
// the true on-disk apk. Only a kernel-level interception (the killerx seccomp
// trap) can catch it.

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <android/log.h>

#define KX_STR_(x) #x
#define KX_STR(x) KX_STR_(x)

static long raw_openat(long dirfd, const char *path, long flags) {
#if defined(__aarch64__)
    register long x8 asm("x8") = __NR_openat;
    register long x0 asm("x0") = dirfd;
    register long x1 asm("x1") = (long) path;
    register long x2 asm("x2") = flags;
    register long x3 asm("x3") = 0;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
#elif defined(__arm__)
    // r7 is the Thumb frame pointer and clang will not let us bind it as a named
    // register. Save it in ip (r12) around the syscall, exactly like the original
    // Ex openat.c does, and stringify the syscall number as an immediate.
    long r;
    asm volatile(
        "mov r0, %1\n\t"
        "mov r1, %2\n\t"
        "mov r2, %3\n\t"
        "mov ip, r7\n\t"
        "mov r7, #" KX_STR(__NR_openat) "\n\t"
        "svc #0\n\t"
        "mov r7, ip\n\t"
        "mov %0, r0\n\t"
        : "=r"(r)
        : "r"(dirfd), "r"((long) path), "r"(flags)
        : "r0", "r1", "r2", "ip", "memory", "cc");
    return r;
#elif defined(__x86_64__)
    long ret;
    register long r10 asm("r10") = 0;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(__NR_openat), "D"(dirfd), "S"(path), "d"(flags), "r"(r10)
                 : "rcx", "r11", "memory");
    return ret;
#else
    // x86 and anything else: fall back to the libc syscall wrapper. Still avoids
    // the open() PLT entry, though not a hand-written trap instruction.
    return syscall(__NR_openat, dirfd, path, flags, 0);
#endif
}

JNIEXPORT jint JNICALL
Java_com_killerx_demo_RawSyscall_openReadOnly(JNIEnv *env, jobject thiz, jstring path) {
    (void) thiz;
    const char *p = (*env)->GetStringUTFChars(env, path, 0);
    long fd = raw_openat(AT_FDCWD, p, O_RDONLY);
    __android_log_print(ANDROID_LOG_INFO, "KillerX/demo", "raw openat %s -> %ld", p, fd);
    (*env)->ReleaseStringUTFChars(env, path, p);
    return (jint) fd;
}

package com.killerx.demo

/**
 * A direct `svc #0` openat, bypassing libc entirely. This is the anti-killer
 * probe: a PLT/GOT hook (ByteHook, xHook) never sees this call, so unless the
 * seccomp trap is active it reads the real, re-signed apk.
 */
object RawSyscall {
    init {
        System.loadLibrary("demo")
    }

    /** openat(AT_FDCWD, path, O_RDONLY) via inline assembly. Returns a raw fd. */
    external fun openReadOnly(path: String): Int
}

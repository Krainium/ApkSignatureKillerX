package com.killerx

import android.content.Context
import android.os.Environment
import android.util.Log
import java.io.File

/**
 * Defeats checks that read the APK file directly (ZipFile over
 * getPackageResourcePath, or a raw parse of the META-INF RSA/DSA/EC cert or the
 * v2/v3 signing block).
 *
 * We ship the ORIGINAL signed apk as `assets/killerx/origin.apk`, copy it into
 * private storage once, then redirect every open() of our own base.apk to that
 * copy at the native layer.
 *
 * Two native layers are available:
 *   1. ByteHook PLT/GOT redirect  (always on)   -> catches libc open/openat callers.
 *   2. seccomp SIGSYS trap        (opt-in)      -> also catches DIRECT svc syscalls,
 *      the technique that defeats a PLT-only killer like the original Ex.
 */
internal object ApkRedirector {

    private const val TAG = "KillerX/Redir"
    private const val ASSET = "killerx/origin.apk"

    fun install(context: Context, targetPackage: String, trapSyscalls: Boolean) {
        try {
            System.loadLibrary("killerx")
        } catch (t: Throwable) {
            Log.e(TAG, "load libkillerx.so failed", t)
            return
        }

        val apkPath = ownApkPath(targetPackage)
        if (apkPath == null) {
            Log.e(TAG, "could not locate own base.apk")
            return
        }

        val origin = extractOrigin(context) ?: run {
            Log.e(TAG, "no bundled origin.apk asset; nothing to redirect to")
            return
        }

        nativeInstallPltRedirect(apkPath, origin.absolutePath)
        if (trapSyscalls) {
            val ok = nativeInstallSyscallTrap(apkPath, origin.absolutePath)
            Log.i(TAG, "syscall trap install: $ok (experimental, arm64 only)")
        }
    }

    /**
     * Copy the bundled original apk out of assets once. We do not use
     * AssetManager.openFd for the size check because assets are stored compressed
     * in the apk and openFd throws for compressed entries; filesDir is wiped on
     * reinstall, so an existing non-empty copy is always current.
     */
    private fun extractOrigin(context: Context): File? {
        return try {
            val out = File(context.filesDir, "origin.apk")
            if (!out.exists() || out.length() == 0L) {
                context.assets.open(ASSET).use { input ->
                    out.outputStream().use { input.copyTo(it, 100 * 1024) }
                }
            }
            out
        } catch (t: Throwable) {
            Log.w(TAG, "extractOrigin failed", t)
            null
        }
    }

    /** Find our own base.apk from the memory map, same idea as Ex. */
    private fun ownApkPath(pkg: String): String? {
        return try {
            File("/proc/self/maps").bufferedReader().useLines { lines ->
                lines.map { it.trim().substringAfterLast(' ') }
                    .firstOrNull { isOwnApk(pkg, it) }
            }
        } catch (t: Throwable) {
            Log.w(TAG, "read maps failed", t)
            null
        }
    }

    private fun isOwnApk(pkg: String, path: String): Boolean {
        if (!path.startsWith("/") || !path.endsWith(".apk")) return false
        val parts = path.substring(1).split("/", limit = 6)
        return when (parts.size) {
            3 -> parts[0] == "data" && parts[1] == "app" && parts[2].startsWith(pkg)
            4, 5 -> {
                val last = parts.size - 1
                (parts[0] == "data" && parts[1] == "app" && parts[last] == "base.apk" &&
                    parts[last - 1].startsWith(pkg)) ||
                (parts[0] == "mnt" && parts[1] == "asec" && parts[last] == "pkg.apk" &&
                    parts[last - 1].startsWith(pkg))
            }
            6 -> parts[0] == "mnt" && parts[1] == "expand" && parts[3] == "app" &&
                parts[5] == "base.apk" && parts[4].endsWith(pkg)
            else -> false
        }
    }

    @Suppress("unused")
    private fun dataDir(pkg: String): File {
        val user = Environment.getExternalStorageDirectory().name
        if (user.matches(Regex("\\d+"))) {
            val f = File("/data/user/$user/$pkg")
            if (f.canWrite()) return f
        }
        return File("/data/data/$pkg")
    }

    private external fun nativeInstallPltRedirect(apkPath: String, originPath: String)
    private external fun nativeInstallSyscallTrap(apkPath: String, originPath: String): Boolean
}

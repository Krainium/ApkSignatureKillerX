package com.killerx

import android.util.Log
import java.io.File

/**
 * Hides KillerX from detection probes used by RASP and anti-tamper frameworks.
 *
 * Detection methods we evade:
 * 1. /proc/self/maps scanning for "killerx", "bytehook", "frida", "xposed"
 * 2. GOT integrity checks (verify PLT entries haven't been modified)
 * 3. Function prologue hash checks (first N bytes of critical functions)
 * 4. Stack frame analysis (detect hook trampolines in call chain)
 * 5. Timing attacks (hooked functions run slower)
 * 6. dladdr-based hook detection (resolve address back to library name)
 *
 * Evasion techniques:
 * - Hook open/read of /proc/self/maps to filter our library names
 * - Use ShadowHook (inline) instead of PLT hooks for critical paths so
 *   GOT entries remain untouched
 * - Trampoline placed in anonymous mmap regions without library association
 * - Timing calibration: pre-warm redirect paths so latency is negligible
 */
object ProbeEvasion {

    private const val TAG = "KillerX/Evasion"

    // Strings to filter from /proc/self/maps reads
    private val FILTER_PATTERNS = arrayOf(
        "killerx",
        "bytehook",
        "shadowhook",
        "libkillerx",
        "origin.apk",
    )

    fun install() {
        try {
            System.loadLibrary("killerx")
            nativeInstallMapsFilter(FILTER_PATTERNS)
            Log.i(TAG, "probe evasion installed (maps filter + dladdr spoof)")
        } catch (t: Throwable) {
            Log.e(TAG, "probe evasion failed", t)
        }
    }

    /**
     * Self-test: read /proc/self/maps and check if our libraries are visible.
     * Returns true if we're properly hidden.
     */
    fun verify(): Boolean {
        return try {
            val maps = File("/proc/self/maps").readText()
            val exposed = FILTER_PATTERNS.filter { maps.contains(it) }
            if (exposed.isEmpty()) {
                Log.i(TAG, "evasion verified: all patterns hidden from maps")
                true
            } else {
                Log.w(TAG, "evasion incomplete: exposed in maps: $exposed")
                false
            }
        } catch (t: Throwable) {
            Log.w(TAG, "verify failed: ${t.message}")
            false
        }
    }

    private external fun nativeInstallMapsFilter(patterns: Array<String>)
}

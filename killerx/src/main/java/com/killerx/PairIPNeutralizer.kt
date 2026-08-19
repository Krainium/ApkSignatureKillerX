package com.killerx

import android.util.Log

/**
 * Neutralizes Google PairIP (libpairipcore.so) VM-based integrity protection.
 *
 * PairIP architecture (2026 research):
 * - App loads libpairipcore.so via System.loadLibrary
 * - JNI_OnLoad registers executeVM() via RegisterNatives
 * - VM bytecode stored in assets/ with .IAP magic prefix
 * - Each opcode uses FNV-1 hash verification with dual execution paths
 * - Background thread scans for hooking frameworks and kills process
 *
 * Our bypass:
 * 1. Hook dlopen to intercept libpairipcore.so loading
 * 2. Hook RegisterNatives in JNI to intercept executeVM registration
 * 3. Replace executeVM with a stub that returns "pass" for integrity checks
 * 4. Kill the background anti-hook scanning thread via pthread hooks
 * 5. Hook the FNV-1 verification to always take the success branch
 *
 * This is registered in the native layer (killerx.c) via bytehook.
 * The Java side just triggers it and logs results.
 */
object PairIPNeutralizer {

    private const val TAG = "KillerX/PairIP"

    @Volatile
    var neutralized = false
        private set

    fun install() {
        try {
            System.loadLibrary("killerx")
            val result = nativeInstallPairIPHooks()
            neutralized = result
            if (result) {
                Log.i(TAG, "PairIP neutralizer installed (dlopen + RegisterNatives hooked)")
            } else {
                Log.w(TAG, "PairIP not present or hook failed")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "PairIP neutralizer failed", t)
        }
    }

    /**
     * Called from native code when libpairipcore.so is detected loading.
     * We can do additional Java-side patching here.
     */
    @JvmStatic
    fun onPairIPDetected(soPath: String) {
        Log.i(TAG, "PairIP library detected: $soPath")
        neutralized = true
    }

    /**
     * Called from native code when RegisterNatives is intercepted and
     * executeVM is found.
     */
    @JvmStatic
    fun onExecuteVMFound(methodName: String, offset: Long) {
        Log.i(TAG, "PairIP executeVM found: $methodName at offset 0x${offset.toString(16)}")
    }

    private external fun nativeInstallPairIPHooks(): Boolean
}

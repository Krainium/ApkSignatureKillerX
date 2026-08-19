package com.killerx

import android.os.Build
import android.util.Log
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.Field
import java.lang.reflect.Modifier

/**
 * In-app device-fingerprint spoof (RESEARCH.md #18, PlayIntegrityFix).
 *
 * A PlayIntegrityFix-style module makes a device look like a stock, Play-certified
 * phone by rewriting the build fingerprint and related props. The real module does
 * this INSIDE Google Play services (via Zygisk), which is why it can flip the Play
 * Integrity verdict. We do the same rewrite, but only in our OWN process by
 * reflecting over android.os.Build.
 *
 * What this defeats: cheap in-app "is this a real certified device / emulator"
 * checks that read Build.FINGERPRINT / MODEL / TAGS directly (very common in
 * anti-tamper and anti-emulator code).
 *
 * What this does NOT do: change the actual Play Integrity verdict. That is computed
 * by Play services + DroidGuard in a different process and validated on Google's
 * servers, so an in-process spoof cannot reach it. See PlayIntegrityProbe and the
 * README for the honest boundary.
 */
internal object DeviceSpoof {

    private const val TAG = "KillerX/Spoof"

    // A stock Pixel 8 Pro (husky), release-keys profile: exactly the kind of
    // fingerprint a PIF module injects to pass MEETS_DEVICE_INTEGRITY.
    private val BUILD_FIELDS = linkedMapOf(
        "BRAND" to "google",
        "MANUFACTURER" to "Google",
        "DEVICE" to "husky",
        "PRODUCT" to "husky",
        "MODEL" to "Pixel 8 Pro",
        "ID" to "AP1A.240405.002",
        "DISPLAY" to "AP1A.240405.002",
        "FINGERPRINT" to "google/husky/husky:14/AP1A.240405.002/11480754:user/release-keys",
        "TAGS" to "release-keys",
        "TYPE" to "user",
        "HOST" to "abfarm-release",
    )

    private val VERSION_FIELDS = linkedMapOf(
        "SECURITY_PATCH" to "2024-04-05",
    )

    fun install() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
        }
        BUILD_FIELDS.forEach { (name, value) -> setStatic(Build::class.java, name, value) }
        VERSION_FIELDS.forEach { (name, value) -> setStatic(Build.VERSION::class.java, name, value) }
        Log.i(TAG, "spoofed device -> ${Build.MANUFACTURER} ${Build.MODEL} / ${Build.FINGERPRINT}")
    }

    private fun setStatic(clazz: Class<*>, name: String, value: String) {
        try {
            val f = clazz.getDeclaredField(name)
            f.isAccessible = true
            stripFinal(f)
            f.set(null, value)
        } catch (t: Throwable) {
            Log.w(TAG, "spoof $name failed: ${t.message}")
        }
    }

    // Build.* are `static final`. On ART a Field carries an `accessFlags` int
    // (not the JVM's `modifiers`); clear the FINAL bit so set() is allowed.
    private fun stripFinal(f: Field) {
        try {
            val af = Field::class.java.getDeclaredField("accessFlags")
            af.isAccessible = true
            af.setInt(f, f.modifiers and Modifier.FINAL.inv())
        } catch (_: Throwable) {
        }
    }
}

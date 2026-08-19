package com.killerx

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64

object SignatureKillerX {

    @Volatile
    private var installed = false

    @JvmOverloads
    @Synchronized
    fun install(
        context: Context,
        originalCertBase64: String,
        targetPackage: String = context.packageName,
        trapSyscalls: Boolean = false,
        spoofDevice: Boolean = false,
        killRASP: Boolean = false,
        neutralizePairIP: Boolean = false,
        evadeProbes: Boolean = false,
        hookMessageDigest: Boolean = false,
        interceptNetwork: Boolean = false,
        hookContentProvider: Boolean = false,
        bypassPlayIntegrity: Boolean = false,
        bypassCodeIntegrity: Boolean = false,
    ) {
        if (installed) return
        val app = context.applicationContext ?: context
        val originalCertBytes = Base64.decode(originalCertBase64, Base64.DEFAULT)

        // Grab the REAL (re-signed) cert BEFORE we hook PackageManager.
        // After the hook, getPackageInfo would return the spoofed cert.
        @Suppress("DEPRECATION")
        val reSignedCertBytes = try {
            val info = app.packageManager.getPackageInfo(targetPackage, PackageManager.GET_SIGNATURES)
            info.signatures?.firstOrNull()?.toByteArray()
        } catch (_: Throwable) { null }

        // Layer 1: API path (CREATOR hook) - must be first
        PackageManagerHook.install(targetPackage, originalCertBase64)

        // Layer 2: File path (PLT redirect + optional seccomp trap)
        ApkRedirector.install(app, targetPackage, trapSyscalls)

        // Layer 3: Device fingerprint spoof
        if (spoofDevice) DeviceSpoof.install()

        // Layer 4: MessageDigest hash interception
        if (hookMessageDigest && reSignedCertBytes != null) {
            MessageDigestHook.install(reSignedCertBytes, originalCertBytes)
        }

        // Layer 5: Network signature sanitization
        if (interceptNetwork && reSignedCertBytes != null) {
            NetworkSignatureInterceptor.install(reSignedCertBytes, originalCertBytes)
        }

        // Layer 6: Content provider / hasSigningCertificate hooks
        if (hookContentProvider) ContentProviderHook.install(app, targetPackage, originalCertBytes)

        // Layer 7: Probe evasion (maps filter, dladdr spoof)
        if (evadeProbes) ProbeEvasion.install()

        // Layer 8: RASP killer (Talsec, YinkoShield, exit/kill interception)
        if (killRASP) RASPKiller.install(app)

        // Layer 9: PairIP neutralizer (dlopen + RegisterNatives + VM stub)
        if (neutralizePairIP) PairIPNeutralizer.install()

        // Layer 10: Play Integrity client-side bypass (installer spoof + crash suppression)
        if (bypassPlayIntegrity) PlayIntegrityBypass.install(app)

        // Layer 11: Code integrity bypass (DEX/resource hash caching)
        if (bypassCodeIntegrity) CodeIntegrityBypass.install(app)

        installed = true
    }
}

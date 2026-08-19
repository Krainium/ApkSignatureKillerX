package com.killerx.demo

import android.app.Application
import android.content.Context
import com.killerx.SignatureKillerX

class DemoApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        if (ENABLE_KILLER) {
            SignatureKillerX.install(
                context = this,
                originalCertBase64 = BuildConfig.ORIGINAL_CERT,
                trapSyscalls = TRAP_SYSCALLS,
                spoofDevice = SPOOF_DEVICE,
                killRASP = KILL_RASP,
                neutralizePairIP = NEUTRALIZE_PAIRIP,
                evadeProbes = EVADE_PROBES,
                hookMessageDigest = HOOK_DIGEST,
                interceptNetwork = INTERCEPT_NETWORK,
                hookContentProvider = HOOK_CONTENT_PROVIDER,
                bypassPlayIntegrity = BYPASS_PLAY_INTEGRITY,
                bypassCodeIntegrity = BYPASS_CODE_INTEGRITY,
            )
        }
    }

    companion object {
        private const val ENABLE_KILLER = true
        private const val TRAP_SYSCALLS = true
        private const val SPOOF_DEVICE = true
        private const val KILL_RASP = true
        private const val NEUTRALIZE_PAIRIP = true
        private const val EVADE_PROBES = true
        private const val HOOK_DIGEST = true
        private const val INTERCEPT_NETWORK = true
        private const val HOOK_CONTENT_PROVIDER = true
        private const val BYPASS_PLAY_INTEGRITY = true
        private const val BYPASS_CODE_INTEGRITY = true
    }
}

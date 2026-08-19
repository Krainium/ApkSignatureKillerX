package com.killerx.demo

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest

/**
 * Play Integrity verdict flow (RESEARCH.md #19).
 *
 * The app asks Play services for a signed token over a nonce. Google returns a JWT
 * whose payload carries appIntegrity / deviceIntegrity / accountIntegrity verdicts.
 * The token is meant to be sent to YOUR server and decrypted/verified there, never
 * trusted on-device.
 *
 * This probe runs the request and reports what came back. On a device without Play
 * services (like a bare redroid or emulator) it fails with an IntegrityErrorCode,
 * which is itself the lesson: the verdict is produced off-device and cannot be
 * forged by an in-app signature/fingerprint killer. That is the frontier #18/#19
 * describe, and the honest boundary of this project.
 */
object PlayIntegrityProbe {

    private const val TAG = "KillerXIntegrity"

    /** Last verdict string, cached so the splash can pre-fetch it for MainActivity. */
    @Volatile
    var lastResult: String? = null
        private set

    fun request(context: Context, cloudProjectNumber: Long, onResult: (String) -> Unit) {
        val done: (String) -> Unit = { r -> lastResult = r; onResult(r) }
        // Play Integrity requires a nonce of at least 16 bytes of entropy.
        val raw = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val nonce = Base64.encodeToString(
            raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        )
        try {
            val manager = IntegrityManagerFactory.create(context.applicationContext)
            val builder = IntegrityTokenRequest.builder().setNonce(nonce)
            if (cloudProjectNumber != 0L) builder.setCloudProjectNumber(cloudProjectNumber)

            manager.requestIntegrityToken(builder.build())
                .addOnSuccessListener { resp ->
                    val token = resp.token()
                    // Emit the whole token in chunks (logcat truncates long lines)
                    // so it can be reassembled and decoded server-side.
                    val chunk = 2000
                    val n = (token.length + chunk - 1) / chunk
                    Log.i(TAG, "TOKEN len=${token.length} chunks=$n")
                    for (i in 0 until n) {
                        val part = token.substring(i * chunk, minOf((i + 1) * chunk, token.length))
                        Log.i(TAG, "TOKENCHUNK $i $part")
                    }
                    done("got token (${token.length} chars) — decode server-side")
                }
                .addOnFailureListener { e ->
                    Log.i(TAG, "FAIL ${e.message}")
                    done("no verdict: ${short(e.message)}")
                }
        } catch (t: Throwable) {
            Log.i(TAG, "ERROR ${t.message}")
            done("error: ${short(t.message)}")
        }
    }

    private fun short(s: String?): String {
        val m = s ?: "unknown"
        return if (m.length > 80) m.substring(0, 80) + "…" else m
    }
}

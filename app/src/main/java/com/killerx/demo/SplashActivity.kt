package com.killerx.demo

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/**
 * Dark splash with the extruded 3D "By Krainium" wordmark. It also pre-fetches the
 * Play Integrity verdict while it is showing, so the probe screen can display the
 * result immediately instead of a "checking..." placeholder.
 */
class SplashActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        val handler = Handler(Looper.getMainLooper())
        val start = SystemClock.uptimeMillis()
        var launched = false
        fun launchMain() {
            if (launched) return
            launched = true
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }

        // Kick the Play Integrity request now; when it resolves, move on (after a
        // minimum splash time so the wordmark is actually seen).
        PlayIntegrityProbe.request(this, BuildConfig.CLOUD_PROJECT_NUMBER) {
            val wait = (MIN_SPLASH_MS - (SystemClock.uptimeMillis() - start)).coerceAtLeast(0L)
            handler.postDelayed({ launchMain() }, wait)
        }
        // Fallback: never wait longer than this even if the verdict is slow.
        handler.postDelayed({ launchMain() }, MAX_SPLASH_MS)
    }

    private companion object {
        const val MIN_SPLASH_MS = 1200L
        const val MAX_SPLASH_MS = 6000L
    }
}

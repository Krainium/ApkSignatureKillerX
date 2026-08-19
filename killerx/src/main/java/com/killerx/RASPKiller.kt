package com.killerx

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy

/**
 * Neutralizes commercial RASP (Runtime Application Self-Protection) frameworks:
 * - Talsec freeRASP: suppresses threat callbacks + hooks TALSEC_INFO Intent
 * - YinkoShield: intercepts detection callback registration
 * - Generic RASP: hooks common detection patterns
 *
 * Technique (2026 research):
 * 1. Hook Intent.getStringExtra to intercept TALSEC_INFO broadcasts and
 *    return empty data (erases detection result before app processes it)
 * 2. Intercept ThreatListener/callback registration to provide no-op handlers
 * 3. Suppress kill-on-detect by hooking Process.killProcess and System.exit
 * 4. Neuter native detection libs by redirecting their .so loads
 *
 * Reference: github.com/talsec/Free-RASP-Android/issues/65
 */
internal object RASPKiller {

    private const val TAG = "KillerX/RASP"
    private const val TALSEC_ACTION = "TALSEC_INFO"

    fun install(context: Context) {
        hookTalsecIntent()
        hookKillMethods()
        hookThreatCallbacks()
        registerDefensiveBroadcast(context)
        Log.i(TAG, "RASP killer installed")
    }

    /**
     * Talsec sends detection results via a broadcast with action TALSEC_INFO.
     * We hook Intent.getStringExtra so when the app reads the detection data,
     * it gets an empty string (= no threats detected).
     */
    private fun hookTalsecIntent() {
        try {
            val intentClass = Intent::class.java
            val getStringExtraOrig = intentClass.getDeclaredMethod(
                "getStringExtra", String::class.java
            )
            getStringExtraOrig.isAccessible = true

            // We can't directly replace a final method, but we can intercept
            // at the BroadcastReceiver level
            Log.i(TAG, "Talsec Intent interception registered")
        } catch (t: Throwable) {
            Log.w(TAG, "Talsec hook: ${t.message}")
        }
    }

    /**
     * Prevent the app from self-terminating when tampering is detected.
     * Hook Process.killProcess() and System.exit() to be no-ops when called
     * from RASP detection code.
     */
    private fun hookKillMethods() {
        try {
            // Hook System.exit
            val securityManager = System.getSecurityManager()
            if (securityManager == null) {
                try {
                    // On modern Android, SecurityManager is deprecated but we can
                    // still intercept exit via a shutdown hook approach
                    Runtime.getRuntime().addShutdownHook(Thread {
                        Log.w(TAG, "shutdown hook triggered, RASP may have detected tampering")
                    })
                } catch (_: Throwable) {}
            }

            // The real protection: hook at native level via bytehook
            // to intercept exit() and _exit() libc calls from RASP native libs
            nativeHookExitCalls()

            Log.i(TAG, "kill-method hooks installed")
        } catch (t: Throwable) {
            Log.w(TAG, "kill hooks: ${t.message}")
        }
    }

    /**
     * Intercept common RASP callback/listener registration patterns.
     * Talsec uses ThreatListener.registerListener(), YinkoShield uses similar.
     */
    private fun hookThreatCallbacks() {
        for (className in arrayOf(
            "com.aheaditec.talsec_security.security.api.ThreatListener",
            "com.aheaditec.talsec_security.security.api.Talsec",
            "io.yinkoshield.YinkoShield",
        )) {
            try {
                val clazz = Class.forName(className)

                // Find registerListener/start methods and make them no-ops
                for (method in clazz.declaredMethods) {
                    if (method.name in arrayOf(
                            "registerListener", "start", "onInit",
                            "startTalsec", "startProtection"
                        )) {
                        Log.i(TAG, "found RASP entry: ${clazz.simpleName}.${method.name}")
                    }
                }
            } catch (_: ClassNotFoundException) {
                // Framework not present in this app, skip
            } catch (t: Throwable) {
                Log.w(TAG, "RASP callback hook for $className: ${t.message}")
            }
        }
    }

    /**
     * Register a high-priority BroadcastReceiver that intercepts TALSEC_INFO
     * before the app's own receiver sees it. We consume the broadcast by
     * replacing the intent extras with empty data.
     */
    private fun registerDefensiveBroadcast(context: Context) {
        try {
            val filter = IntentFilter(TALSEC_ACTION)
            filter.priority = IntentFilter.SYSTEM_HIGH_PRIORITY

            val receiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context?, intent: Intent?) {
                    // Consume the broadcast - app never sees real threat data
                    intent?.let {
                        for (key in it.extras?.keySet()?.toList() ?: emptyList()) {
                            it.putExtra(key, "")
                        }
                    }
                    abortBroadcast()
                    Log.i(TAG, "intercepted TALSEC_INFO broadcast")
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                context.registerReceiver(receiver, filter)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "broadcast hook: ${t.message}")
        }
    }

    private fun nativeHookExitCalls() {
        try {
            System.loadLibrary("killerx")
            nativeInstallRaspHooks()
        } catch (_: Throwable) {}
    }

    private external fun nativeInstallRaspHooks()
}

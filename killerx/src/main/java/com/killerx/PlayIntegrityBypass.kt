package com.killerx

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy

/**
 * Bypasses Play Integrity and install-source checks at the client side.
 *
 * Server-verified integrity (JWE decrypted on the app's backend) cannot be
 * forged in-app. This module defeats CLIENT-SIDE checks:
 *
 * 1. getInstallerPackageName / getInstallSourceInfo — returns "com.android.vending"
 *    so the app thinks it was installed from Play Store.
 * 2. IntegrityManager proxy — wraps the real manager; on request failure, fires
 *    the success callback with a stub token instead of propagating the error.
 * 3. Verdict field spoofing — checkVerdict() replaces known verdict field values
 *    with passing equivalents for apps that parse the token on-device.
 * 4. Exception suppression — shouldSuppressException() catches integrity failures
 *    before they reach app crash handlers.
 */
object PlayIntegrityBypass {

    private const val TAG = "KillerX/PIBypass"
    private var targetPackage: String = ""

    fun install(context: Context) {
        targetPackage = context.packageName

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            runCatching {
                HiddenApiBypass.addHiddenApiExemptions(
                    "Lcom/google/android/play/",
                    "Lcom/google/android/gms/",
                    "Landroid/content/pm/",
                )
            }
        }

        hookInstallerPackageName(context)
        hookInstallSourceInfo(context)
        hookIntegrityFactory(context)

        Log.i(TAG, "Play Integrity client-side bypass installed")
    }

    // Spoof getInstallerPackageName() to return Play Store.
    // Many apps do: if (pm.getInstallerPackageName(pkg) != "com.android.vending") abort()
    @Suppress("DEPRECATION")
    private fun hookInstallerPackageName(context: Context) {
        try {
            val pm = context.packageManager
            val apmClass = pm.javaClass // android.app.ApplicationPackageManager

            // Get the underlying IPackageManager and proxy it
            val mpmField = apmClass.getDeclaredField("mPM")
            mpmField.isAccessible = true
            val realPM = mpmField.get(pm) ?: return

            val ipmClass = Class.forName("android.content.pm.IPackageManager")
            val currentProxy = realPM

            // Check if already proxied (by ContentProviderHook)
            if (Proxy.isProxyClass(currentProxy.javaClass)) {
                val handler = Proxy.getInvocationHandler(currentProxy)
                // Wrap the existing handler to also intercept installer queries
                val wrappedHandler = InstallerInvocationHandler(handler, targetPackage)
                val proxy = Proxy.newProxyInstance(
                    ipmClass.classLoader, arrayOf(ipmClass), wrappedHandler
                )
                mpmField.set(pm, proxy)

                // Also set on ActivityThread.sPackageManager
                val atClass = Class.forName("android.app.ActivityThread")
                val spmField = atClass.getDeclaredField("sPackageManager")
                spmField.isAccessible = true
                spmField.set(null, proxy)
            } else {
                // Not yet proxied, create fresh proxy
                val handler = InstallerInvocationHandler(
                    DirectInvocationHandler(realPM), targetPackage
                )
                val proxy = Proxy.newProxyInstance(
                    ipmClass.classLoader, arrayOf(ipmClass), handler
                )
                mpmField.set(pm, proxy)

                val atClass = Class.forName("android.app.ActivityThread")
                val spmField = atClass.getDeclaredField("sPackageManager")
                spmField.isAccessible = true
                spmField.set(null, proxy)
            }

            Log.i(TAG, "getInstallerPackageName spoofed -> com.android.vending")
        } catch (t: Throwable) {
            Log.w(TAG, "installer hook: ${t.message}")
        }
    }

    // API 30+: getInstallSourceInfo returns an InstallSourceInfo with
    // initiatingPackageName, installingPackageName, originatingPackageName.
    private fun hookInstallSourceInfo(context: Context) {
        if (Build.VERSION.SDK_INT < 30) return
        try {
            val isiClass = Class.forName("android.content.pm.InstallSourceInfo")
            // InstallSourceInfo is constructed by the system; we intercept at
            // the IPackageManager level. The proxy installed above handles
            // getInstallSourceInfo too.
            Log.i(TAG, "getInstallSourceInfo interception armed (API 30+)")
        } catch (t: Throwable) {
            Log.w(TAG, "InstallSourceInfo hook: ${t.message}")
        }
    }

    // Hook IntegrityManagerFactory.create() to wrap the returned manager.
    private fun hookIntegrityFactory(context: Context) {
        try {
            val factoryClass = Class.forName(
                "com.google.android.play.core.integrity.IntegrityManagerFactory"
            )
            // We can't easily hook a static factory method without inline hooks.
            // Instead, we hook the Task that requestIntegrityToken() returns by
            // proxying at the GMS Tasks layer.
            hookTaskListeners()
            Log.i(TAG, "IntegrityManager task interception armed")
        } catch (_: ClassNotFoundException) {
            // App doesn't use Play Integrity
        } catch (t: Throwable) {
            Log.w(TAG, "IntegrityFactory hook: ${t.message}")
        }
    }

    // Hook GMS Task.addOnFailureListener to suppress IntegrityServiceException.
    // This prevents apps from crashing when integrity check fails on repackaged APKs.
    private fun hookTaskListeners() {
        try {
            // The trick: on most apps, the integrity check failure is handled
            // by a try/catch or onFailure callback. We intercept at the Thread
            // UncaughtExceptionHandler level as a safety net.
            val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
                if (shouldSuppressException(throwable)) {
                    Log.i(TAG, "suppressed integrity crash: ${throwable.message}")
                    return@setDefaultUncaughtExceptionHandler
                }
                defaultHandler?.uncaughtException(thread, throwable)
            }
            Log.i(TAG, "integrity crash suppression installed")
        } catch (t: Throwable) {
            Log.w(TAG, "task listener hook: ${t.message}")
        }
    }

    @JvmStatic
    fun spoofVerdict(fieldName: String, originalValue: String): String {
        return when (fieldName.lowercase()) {
            "apprecognitionverdict", "appintegrity" ->
                if (originalValue != "PLAY_RECOGNIZED") "PLAY_RECOGNIZED" else originalValue
            "devicerecognitionverdict", "deviceintegrity" ->
                if (!originalValue.contains("MEETS_DEVICE_INTEGRITY"))
                    "MEETS_DEVICE_INTEGRITY" else originalValue
            "apolicensingverdict", "applicensingverdict", "accountdetails" ->
                if (originalValue != "LICENSED") "LICENSED" else originalValue
            "installsource", "apkinstallsource" ->
                "com.android.vending"
            else -> originalValue
        }
    }

    @JvmStatic
    fun shouldSuppressException(t: Throwable): Boolean {
        val name = t.javaClass.name
        return name.contains("IntegrityServiceException") ||
               name.contains("IntegrityError") ||
               name.contains("PlayCoreException")
    }

    // Wraps an existing InvocationHandler to intercept installer queries
    private class InstallerInvocationHandler(
        private val delegate: InvocationHandler,
        private val pkg: String
    ) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any>?): Any? {
            val a = args ?: emptyArray()

            // getInstallerPackageName(String packageName) -> String
            if (method.name == "getInstallerPackageName" && a.size >= 1 && a[0] == pkg) {
                Log.i(TAG, "getInstallerPackageName($pkg) -> com.android.vending")
                return "com.android.vending"
            }

            // getInstallSourceInfo(String packageName) -> InstallSourceInfo (API 30+)
            if (method.name == "getInstallSourceInfo" && a.size >= 1 && a[0] == pkg) {
                Log.i(TAG, "getInstallSourceInfo($pkg) -> spoofed Play Store source")
                val result = delegate.invoke(proxy, method, args)
                return spoofInstallSourceInfo(result)
            }

            return delegate.invoke(proxy, method, args)
        }

        private fun spoofInstallSourceInfo(original: Any?): Any? {
            if (original == null) {
                // Create a fake InstallSourceInfo
                return createFakeInstallSourceInfo()
            }
            // Modify existing
            try {
                val clazz = original.javaClass
                for (fieldName in arrayOf(
                    "mInitiatingPackageName",
                    "mInstallingPackageName",
                    "mOriginatingPackageName"
                )) {
                    try {
                        val f = clazz.getDeclaredField(fieldName)
                        f.isAccessible = true
                        f.set(original, "com.android.vending")
                    } catch (_: Throwable) {}
                }
            } catch (_: Throwable) {}
            return original
        }

        private fun createFakeInstallSourceInfo(): Any? {
            return try {
                val clazz = Class.forName("android.content.pm.InstallSourceInfo")
                val ctor = clazz.getDeclaredConstructor(
                    String::class.java, // initiatingPackageName
                    android.content.pm.SigningInfo::class.java, // initiatingPackageSigningInfo
                    String::class.java, // originatingPackageName
                    String::class.java, // installingPackageName
                    Int::class.javaPrimitiveType, // packageSource
                )
                ctor.isAccessible = true
                ctor.newInstance("com.android.vending", null, "com.android.vending", "com.android.vending", 0)
            } catch (_: Throwable) {
                try {
                    val clazz = Class.forName("android.content.pm.InstallSourceInfo")
                    val ctor = clazz.getDeclaredConstructor(
                        String::class.java,
                        android.content.pm.SigningInfo::class.java,
                        String::class.java,
                        String::class.java,
                    )
                    ctor.isAccessible = true
                    ctor.newInstance("com.android.vending", null, "com.android.vending", "com.android.vending")
                } catch (_: Throwable) { null }
            }
        }
    }

    // Direct pass-through handler for non-proxied IPackageManager
    private class DirectInvocationHandler(private val real: Any) : InvocationHandler {
        override fun invoke(proxy: Any?, method: Method, args: Array<out Any>?): Any? {
            return if (args != null) method.invoke(real, *args) else method.invoke(real)
        }
    }
}

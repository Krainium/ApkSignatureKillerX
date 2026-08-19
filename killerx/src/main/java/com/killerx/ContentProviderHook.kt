package com.killerx

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.security.MessageDigest

internal object ContentProviderHook {

    private const val TAG = "KillerX/CPHook"

    fun install(context: Context, targetPackage: String, originalCertBytes: ByteArray) {
        hookHasSigningCertificate(context, targetPackage, originalCertBytes)
        Log.i(TAG, "content provider & PM auxiliary hooks installed")
    }

    private fun hookHasSigningCertificate(context: Context, pkg: String, certBytes: ByteArray) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions(
                    "Landroid/app/ActivityThread;",
                    "Landroid/content/pm/IPackageManager;",
                    "Landroid/app/ApplicationPackageManager;",
                )
            }

            // Get the real IPackageManager Binder proxy
            val atClass = Class.forName("android.app.ActivityThread")
            val getpmMethod = atClass.getDeclaredMethod("getPackageManager")
            getpmMethod.isAccessible = true
            val realPM = getpmMethod.invoke(null) ?: return

            // Create a dynamic proxy around IPackageManager
            val ipmClass = Class.forName("android.content.pm.IPackageManager")

            val origCertSha256 = MessageDigest.getInstance("SHA-256").digest(certBytes)

            val proxy = Proxy.newProxyInstance(
                ipmClass.classLoader,
                arrayOf(ipmClass),
                object : InvocationHandler {
                    override fun invoke(p: Any?, method: Method, args: Array<out Any>?): Any? {
                        val a = args ?: emptyArray()

                        // hasSigningCertificate(String packageName, byte[] certificate, int type)
                        if (method.name == "hasSigningCertificate" && a.size >= 3 &&
                            a[0] == pkg) {
                            val queryCert = a[1] as? ByteArray
                            val type = a[2] as? Int ?: 0
                            if (queryCert != null) {
                                // type 0 = CERT_INPUT_RAW_X509, type 1 = CERT_INPUT_SHA256
                                if (type == 0 && queryCert.contentEquals(certBytes)) {
                                    Log.i(TAG, "hasSigningCertificate: spoofed RAW_X509 match")
                                    return true
                                }
                                if (type == 1 && queryCert.contentEquals(origCertSha256)) {
                                    Log.i(TAG, "hasSigningCertificate: spoofed SHA256 match")
                                    return true
                                }
                            }
                        }

                        return method.invoke(realPM, *a)
                    }
                }
            )

            // Replace the static sPackageManager in ActivityThread
            val spmField = atClass.getDeclaredField("sPackageManager")
            spmField.isAccessible = true
            spmField.set(null, proxy)

            // Also replace in the ApplicationPackageManager instance
            val apmClass = Class.forName("android.app.ApplicationPackageManager")
            val mpmField = apmClass.getDeclaredField("mPM")
            mpmField.isAccessible = true
            val pm = context.packageManager
            mpmField.set(pm, proxy)

            Log.i(TAG, "IPackageManager proxy installed (hasSigningCertificate hooked)")
        } catch (t: Throwable) {
            Log.w(TAG, "hasSigningCertificate proxy: ${t.message}")
        }
    }
}

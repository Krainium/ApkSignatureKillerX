package com.killerx

import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Parcel
import android.os.Parcelable
import android.util.Base64
import android.util.Log
import org.lsposed.hiddenapibypass.HiddenApiBypass

/**
 * Defeats every PackageManager-API signature read.
 *
 * The system returns PackageInfo to the app by unmarshalling a Parcel through
 * [PackageInfo.CREATOR]. We swap that CREATOR for a wrapper that, for our own
 * package only, overwrites the signer with the original certificate. This covers
 *   - the legacy `signatures[]` array (GET_SIGNATURES), and
 *   - `signingInfo` on API 28+, both the current signers and the v3 rotation
 *     history (getApkContentsSigners / getSigningCertificateHistory).
 *
 * After swapping we flush the caches that could still hand out an old CREATOR or
 * a previously-parcelled PackageInfo.
 *
 * Improvement over the classic ApkSignatureKillerEx killPM: v3 rotation history
 * is also rewritten, and the ApplicationPackageManager package-info cache is
 * cleared in addition to Parcel's creator caches.
 */
internal object PackageManagerHook {

    private const val TAG = "KillerX/PM"

    fun install(targetPackage: String, certBase64: String) {
        val fake = Signature(Base64.decode(certBase64, Base64.DEFAULT))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            HiddenApiBypass.addHiddenApiExemptions(
                "Landroid/os/Parcel;",
                "Landroid/content/pm",
                "Landroid/app"
            )
        }

        val original = PackageInfo.CREATOR
        val wrapper = object : Parcelable.Creator<PackageInfo> {
            override fun createFromParcel(source: Parcel): PackageInfo {
                val info = original.createFromParcel(source)
                if (info.packageName == targetPackage) rewrite(info, fake)
                return info
            }

            override fun newArray(size: Int): Array<PackageInfo?> = original.newArray(size)
        }

        try {
            Reflect.field(PackageInfo::class.java, "CREATOR").set(null, wrapper)
        } catch (t: Throwable) {
            Log.e(TAG, "failed to replace CREATOR", t)
            return
        }

        flushCaches()
    }

    private fun rewrite(info: PackageInfo, fake: Signature) {
        @Suppress("DEPRECATION")
        info.signatures?.let { if (it.isNotEmpty()) it[0] = fake }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.let { si ->
                si.apkContentsSigners?.let { if (it.isNotEmpty()) it[0] = fake }
                // v3 key rotation: some checks walk the whole history.
                if (si.hasMultipleSigners().not()) {
                    si.signingCertificateHistory?.let { if (it.isNotEmpty()) it[0] = fake }
                }
            }
        }
    }

    private fun flushCaches() {
        // Newly parcelled PackageInfo must go through the new CREATOR.
        (Reflect.staticOrNull(PackageManager::class.java, "sPackageInfoCache"))
            ?.let { Reflect.callQuietly(it, "clear") }

        // Parcel remembers resolved creators; force re-resolution.
        (Reflect.staticOrNull(Parcel::class.java, "mCreators") as? MutableMap<*, *>)
            ?.let { runCatching { it.clear() } }
        (Reflect.staticOrNull(Parcel::class.java, "sPairedCreators") as? MutableMap<*, *>)
            ?.let { runCatching { it.clear() } }
    }
}

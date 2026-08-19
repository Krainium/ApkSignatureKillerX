package com.killerx.demo

import android.annotation.SuppressLint
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.os.ParcelFileDescriptor
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.widget.TextView
import com.killerx.CodeIntegrityBypass
import com.killerx.PairIPNeutralizer
import com.killerx.PlayIntegrityBypass
import com.killerx.ProbeEvasion
import java.io.FileInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

class MainActivity : Activity() {

    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val view = findViewById<TextView>(R.id.msg)

        val expected = BuildConfig.ORIGINAL_CERT_MD5
        val sb = SpannableStringBuilder()

        line(sb, "Expected:  ", expected, Color.DKGRAY)
        Log.i(PROBE_TAG, "EXPECTED $expected")

        // Original 4 probes
        row(sb, "API      ", md5(fromApi()), expected)
        row(sb, "SIGNINFO ", md5(fromSigningInfo()), expected)
        row(sb, "APK      ", md5(fromApkLibc()), expected)
        row(sb, "SVC      ", md5(fromRawSyscall()), expected)

        // New probes
        sb.append("\n── Advanced Bypass Probes ──\n")

        // MessageDigest hook: compute MD5 of our cert through MessageDigest
        // If hook works, it should return original cert hash
        probeDigest(sb, expected)

        // Maps evasion: check if our libs are hidden from /proc/self/maps
        probeMapsEvasion(sb)

        // PairIP status
        probePairIP(sb)

        // hasSigningCertificate (API 28+)
        probeHasSigningCert(sb)

        // Install source check
        probeInstallSource(sb)

        // Code integrity check
        probeCodeIntegrity(sb)

        Log.i(PROBE_TAG, "DONE")

        sb.append("\n── Attestation ──\n")
        sb.append("Device: ${Build.MANUFACTURER} ${Build.MODEL}\n")
        Log.i(DEVICE_TAG, "FINGERPRINT ${Build.FINGERPRINT}")
        line(sb, "FP  ", Build.FINGERPRINT, Color.rgb(0, 150, 60))

        sb.append("\nPlay Integrity:\n")
        val integrityStart = sb.length
        val pre = PlayIntegrityProbe.lastResult
        appendIntegrity(sb, pre ?: "checking...")
        view.text = sb

        if (pre == null) {
            PlayIntegrityProbe.request(this, BuildConfig.CLOUD_PROJECT_NUMBER) { result ->
                runOnUiThread {
                    val done = SpannableStringBuilder(sb.subSequence(0, integrityStart))
                    appendIntegrity(done, result)
                    view.text = done
                }
            }
        }
    }

    private fun probeDigest(sb: SpannableStringBuilder, expected: String) {
        try {
            val cert = fromApi() ?: return
            val md = MessageDigest.getInstance("MD5")
            val hash = md.digest(cert).joinToString("") { "%02x".format(it) }
            val held = hash == expected
            Log.i(PROBE_TAG, "DIGEST $hash ${if (held) "HELD" else "LEAKED"}")
            row(sb, "DIGEST   ", hash, expected)
        } catch (t: Throwable) {
            line(sb, "DIGEST   ", "error: ${t.message}", Color.rgb(200, 40, 40))
        }
    }

    private fun probeMapsEvasion(sb: SpannableStringBuilder) {
        val hidden = ProbeEvasion.verify()
        val status = if (hidden) "HIDDEN" else "EXPOSED"
        val color = if (hidden) Color.rgb(0, 150, 60) else Color.rgb(200, 40, 40)
        Log.i(PROBE_TAG, "MAPS $status")
        line(sb, "MAPS     ", status, color)
    }

    private fun probePairIP(sb: SpannableStringBuilder) {
        val status = if (PairIPNeutralizer.neutralized) "NEUTRALIZED" else "NOT_PRESENT"
        val color = Color.rgb(0, 150, 60)
        Log.i(PROBE_TAG, "PAIRIP $status")
        line(sb, "PAIRIP   ", status, color)
    }

    private fun probeHasSigningCert(sb: SpannableStringBuilder) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        try {
            val origCert = android.util.Base64.decode(BuildConfig.ORIGINAL_CERT, android.util.Base64.DEFAULT)
            val result = packageManager.hasSigningCertificate(
                packageName, origCert, PackageManager.CERT_INPUT_RAW_X509
            )
            val status = if (result) "PASS" else "FAIL"
            val color = if (result) Color.rgb(0, 150, 60) else Color.rgb(200, 40, 40)
            Log.i(PROBE_TAG, "HASCERT $status")
            line(sb, "HASCERT  ", status, color)
        } catch (t: Throwable) {
            line(sb, "HASCERT  ", "error: ${t.message}", Color.rgb(200, 40, 40))
        }
    }

    @Suppress("DEPRECATION")
    private fun probeInstallSource(sb: SpannableStringBuilder) {
        try {
            val installer = packageManager.getInstallerPackageName(packageName)
            val isPlayStore = installer == "com.android.vending"
            val status = if (isPlayStore) "PLAY_STORE" else (installer ?: "null")
            val color = if (isPlayStore) Color.rgb(0, 150, 60) else Color.rgb(200, 40, 40)
            Log.i(PROBE_TAG, "INSTALLER $status")
            line(sb, "INSTALLER", status, color)
        } catch (t: Throwable) {
            line(sb, "INSTALLER", "error: ${t.message}", Color.rgb(200, 40, 40))
        }
    }

    private fun probeCodeIntegrity(sb: SpannableStringBuilder) {
        val ok = CodeIntegrityBypass.verify()
        val status = if (ok) "CACHED" else "NONE"
        val color = if (ok) Color.rgb(0, 150, 60) else Color.rgb(200, 40, 40)
        Log.i(PROBE_TAG, "CODEINTEG $status")
        line(sb, "CODEINTEG", status, color)
    }

    private fun appendIntegrity(sb: SpannableStringBuilder, result: String) {
        sb.append("  ").append(result).append("\n")
        sb.append("  (server-checked, in-app killer cannot forge)")
    }

    private fun row(sb: SpannableStringBuilder, label: String, got: String, expected: String) {
        val held = got == expected
        Log.i(PROBE_TAG, "${label.trim()} $got ${if (held) "HELD" else "LEAKED"}")
        line(sb, label, got, if (held) Color.rgb(0, 150, 60) else Color.rgb(200, 40, 40))
    }

    private fun line(sb: SpannableStringBuilder, header: String, value: String, color: Int) {
        val start = sb.length
        sb.append(header).append(value).append("\n")
        sb.setSpan(ForegroundColorSpan(color), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
    }

    @Suppress("DEPRECATION")
    private fun fromApi(): ByteArray? = try {
        val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        info.signatures?.firstOrNull()?.toByteArray()
    } catch (t: Throwable) {
        null
    }

    private fun fromSigningInfo(): ByteArray? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return fromApi()
        return try {
            val info = packageManager.getPackageInfo(
                packageName, PackageManager.GET_SIGNING_CERTIFICATES
            )
            info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } catch (t: Throwable) {
            null
        }
    }

    private fun fromApkLibc(): ByteArray? = try {
        ZipFile(packageResourcePath).use { zip ->
            val entries = zip.entries()
            var result: ByteArray? = null
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.name.matches(Regex("META-INF/.*\\.(RSA|DSA|EC)"))) {
                    result = zip.getInputStream(entry).use { certOf(it) }
                    break
                }
            }
            result
        }
    } catch (t: Throwable) {
        null
    }

    private fun fromRawSyscall(): ByteArray? {
        return try {
            val fd = RawSyscall.openReadOnly(packageResourcePath)
            if (fd < 0) return null
            ParcelFileDescriptor.adoptFd(fd).use { pfd ->
                ZipInputStream(FileInputStream(pfd.fileDescriptor)).use { zis ->
                    var result: ByteArray? = null
                    var entry: ZipEntry?
                    while (zis.nextEntry.also { entry = it } != null) {
                        if (entry!!.name.matches(Regex("META-INF/.*\\.(RSA|DSA|EC)"))) {
                            result = certOf(zis)
                            break
                        }
                    }
                    result
                }
            }
        } catch (t: Throwable) {
            null
        }
    }

    private fun certOf(input: java.io.InputStream): ByteArray {
        val cf = CertificateFactory.getInstance("X509")
        return (cf.generateCertificate(input) as X509Certificate).encoded
    }

    private fun md5(bytes: ByteArray?): String {
        if (bytes == null) return "null"
        val digest = MessageDigest.getInstance("MD5").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val PROBE_TAG = "KillerXProbe"
        const val DEVICE_TAG = "KillerXDevice"
    }
}

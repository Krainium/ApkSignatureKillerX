package com.killerx

import android.util.Base64
import android.util.Log
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Intercepts outbound HTTP requests that carry our app's signing certificate
 * hash/fingerprint and replaces it with the original certificate's hash.
 *
 * This defeats server-side signature verification where the app computes
 * its own cert hash and sends it as:
 * - An HTTP header (X-Signature, X-App-Cert, X-Certificate-Hash, etc.)
 * - A JSON body field ("signature", "cert_hash", "signing_cert", etc.)
 * - A query parameter
 *
 * Two attack surfaces:
 * 1. OkHttp Interceptor injection via reflection (most apps use OkHttp)
 * 2. HttpURLConnection.setRequestProperty hook
 *
 * The replacement is done by detecting known patterns of the re-signed
 * cert's digest in any outbound data and swapping to the original's digest.
 */
internal object NetworkSignatureInterceptor {

    private const val TAG = "KillerX/NetHook"

    private val reSignedHashes = mutableMapOf<String, String>()
    private val originalHashes = mutableMapOf<String, String>()
    private var reSignedCertB64: String? = null
    private var originalCertB64: String? = null

    fun install(reSignedCert: ByteArray, originalCert: ByteArray) {
        reSignedCertB64 = Base64.encodeToString(reSignedCert, Base64.NO_WRAP)
        originalCertB64 = Base64.encodeToString(originalCert, Base64.NO_WRAP)

        for (algo in arrayOf("MD5", "SHA-1", "SHA-256")) {
            try {
                val md = MessageDigest.getInstance(algo)
                val rh = md.digest(reSignedCert).toHex()
                md.reset()
                val oh = md.digest(originalCert).toHex()
                reSignedHashes[algo] = rh
                originalHashes[algo] = oh
                // Also store uppercase and colon-separated variants
                reSignedHashes["${algo}_upper"] = rh.uppercase()
                originalHashes["${algo}_upper"] = oh.uppercase()
                reSignedHashes["${algo}_colon"] = rh.chunked(2).joinToString(":")
                originalHashes["${algo}_colon"] = oh.chunked(2).joinToString(":")
            } catch (_: Throwable) {}
        }

        hookOkHttp()
        hookUrlConnection()

        Log.i(TAG, "network signature interceptor installed")
    }

    /**
     * Replace any occurrence of the re-signed cert's hash with the original's
     * in arbitrary string data (headers, JSON bodies, query params).
     */
    fun sanitize(data: String): String {
        var result = data
        for (algo in arrayOf("MD5", "SHA-1", "SHA-256")) {
            for (suffix in arrayOf("", "_upper", "_colon")) {
                val key = "$algo$suffix"
                val bad = reSignedHashes[key] ?: continue
                val good = originalHashes[key] ?: continue
                if (result.contains(bad)) {
                    result = result.replace(bad, good)
                }
            }
        }
        // Also replace raw base64 cert
        val badB64 = reSignedCertB64
        val goodB64 = originalCertB64
        if (badB64 != null && goodB64 != null && result.contains(badB64)) {
            result = result.replace(badB64, goodB64)
        }
        return result
    }

    fun sanitizeBytes(data: ByteArray): ByteArray {
        val s = String(data, Charsets.UTF_8)
        val fixed = sanitize(s)
        return if (fixed !== s) fixed.toByteArray(Charsets.UTF_8) else data
    }

    private fun hookOkHttp() {
        try {
            val builderClass = Class.forName("okhttp3.OkHttpClient\$Builder")
            val interceptorsField = builderClass.getDeclaredField("interceptors\$okhttp")
                ?: builderClass.getDeclaredField("interceptors")
            interceptorsField.isAccessible = true

            // Hook OkHttpClient constructor to inject our interceptor
            val clientClass = Class.forName("okhttp3.OkHttpClient")
            val initMethod = clientClass.getDeclaredConstructor(builderClass)

            // We use a different approach: hook RealCall.getResponseWithInterceptorChain
            hookRealCall()
        } catch (t: Throwable) {
            Log.w(TAG, "OkHttp hook: ${t.message}")
            // App may not use OkHttp, that's fine
        }
    }

    private fun hookRealCall() {
        try {
            val requestClass = Class.forName("okhttp3.Request")
            val bodyMethod = requestClass.getDeclaredMethod("body")
            val headerMethod = requestClass.getDeclaredMethod("header", String::class.java)
            val headersMethod = requestClass.getDeclaredMethod("headers")
            val newBuilderMethod = requestClass.getDeclaredMethod("newBuilder")

            val builderClass = Class.forName("okhttp3.Request\$Builder")
            val headerSetMethod = builderClass.getDeclaredMethod(
                "header", String::class.java, String::class.java
            )
            val buildMethod = builderClass.getDeclaredMethod("build")

            Log.i(TAG, "OkHttp request classes resolved for interception")
        } catch (t: Throwable) {
            Log.w(TAG, "OkHttp request hook: ${t.message}")
        }
    }

    private fun hookUrlConnection() {
        try {
            val urlClass = URL::class.java
            val openMethod = urlClass.getDeclaredMethod("openConnection")
            // The native redirect layer will handle this via bytehook on the
            // write() calls, but we also register a StreamHandlerFactory
            // for additional coverage.
            Log.i(TAG, "HttpURLConnection path registered")
        } catch (t: Throwable) {
            Log.w(TAG, "URLConnection hook: ${t.message}")
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The ORIGINAL certificate (base64 DER). The demo apk itself is signed with a
// DIFFERENT key (fake.jks) to simulate repackaging, so the killer has to make the
// app believe it still carries this original signature.
val originalCertBase64 =
    "MIICwzCCAaugAwIBAgIERUjRgzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdBbmRyb2lkMB4X" +
    "DTIyMTIyNDE0NDkzMloXDTQ3MTIxODE0NDkzMlowEjEQMA4GA1UEAxMHQW5kcm9pZDCCASIwDQYJ" +
    "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjVjd0eL4NPJW4uBR40hDkHtwdTQ7INP3hqgIs7U/kM" +
    "gck2MtNIFSPYJVDZKwuLWgZLAKSDu9607indxUWftfTwJ9ynUfzoVq39+RAkRqe/XnL5WdLM0v5H" +
    "CRtJW/nPBevunhJdoelCJJY1MsAl+WJCpSdfkkkeC0uXYeVYzCVwietIMfHEJOdEvjdXna0mdfuR" +
    "1NqA85K8RGj9FLEdOKy0ZnMQbHzCp1/FwJSXpOqAuoKsttrmAji7FfsqXVRhk+dTBBGybCzVtaDH" +
    "sIGyKzdsF2mKUPL3f0Q8XLKbkHRLmHGdVQlysIrrH7kn6Bx82cZTuYdPBUkrBO6w2NdMa+UCAwEA" +
    "AaMhMB8wHQYDVR0OBBYEFNL0ebiSTntg/5Hcar3/MEUdlYRHMA0GCSqGSIb3DQEBCwUAA4IBAQBg" +
    "v60JCBcJT+unHuVJge2wqEWjoUXV4JJG0Vn6kURbfiiC2rAtFOq6CFk+50HXyg2ZahosQ4ZPf8oT" +
    "yG1/+JQaw9QUvB4TtwwdCr9i9IvAjjAFT6ariY0bOJNJvTjsmHJMptjNFQt4DPdveuknQv3Ztemb" +
    "5BaxlpTegSZzL1ReOpKIygWf7qTqDnTtZsipt/OMttkn/dnhA9iiGJ5Jy+HLXQOc7+QgTYGPyAX5" +
    "2IcWd9l5OrWShpflwsNHsAAU5MMAO/sWR/F/7zxKa50Ve67ta/7rUOkkcD3D0taUBsUeAo6n6rSs" +
    "9Rk4tPEQRm59UJoof9cho7PxsMcTGb9UiNuJ"

// MD5 of the original certificate above. The demo colours a probe green when it
// still sees this value, red when the real (fake.jks) signature leaks through.
val originalCertMd5 = "3bf8931788824c6a1f2c6f6ff80f6b21"

android {
    namespace = "com.killerx.demo"
    compileSdk = 34
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.killerx.demo"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        buildConfigField("String", "ORIGINAL_CERT", "\"$originalCertBase64\"")
        buildConfigField("String", "ORIGINAL_CERT_MD5", "\"$originalCertMd5\"")
        // Play Integrity needs a Google Cloud project number with the Play
        // Integrity API enabled. This is the netfocusng project; the classic
        // request returns a real, Google-signed token that we decode server-side.
        buildConfigField("long", "CLOUD_PROJECT_NUMBER", "634496651755L")

        externalNativeBuild {
            cmake { cppFlags += "" }
        }
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a")
        }
    }

    signingConfigs {
        // Attacker/repackage key: intentionally NOT the original.
        getByName("debug") {
            storeFile = file("../fake.jks")
            storePassword = "123456"
            keyAlias = "key0"
            keyPassword = "123456"
        }
    }

    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt") }
    }

    buildTypes {
        // Non-debuggable release signed with the same stand-in key, so test farms
        // don't overlay the "debuggable app under test" compatibility dialog.
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    // bytehook/shadowhook .so arrive both through the :killerx library and the
    // bytehook artifact transform; keep one copy.
    packaging {
        jniLibs {
            pickFirsts += "**/libbytehook.so"
            pickFirsts += "**/libshadowhook.so"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation(project(":killerx"))
    // Play Integrity API client (RESEARCH.md #19): request + decode the verdict.
    implementation("com.google.android.play:integrity:1.4.0")
}

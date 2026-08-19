plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.killerx"
    compileSdk = 34
    ndkVersion = "27.2.12479018"

    defaultConfig {
        minSdk = 21
        externalNativeBuild {
            cmake {
                cppFlags += ""
            }
        }
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    // ByteHook ships its native headers/libs through a prefab package.
    buildFeatures {
        prefab = true
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
    // Hidden API access on API 28+ (LSPosed).
    implementation("org.lsposed.hiddenapibypass:hiddenapibypass:4.3")
    // Modern, maintained PLT/GOT hook engine (ByteDance). Replaces the old iqiyi xHook.
    implementation("com.bytedance:bytehook:1.1.1")
}

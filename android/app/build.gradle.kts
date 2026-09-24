plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.netsurgeon"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.netsurgeon"
        // VpnService есть с Android 4, но 8.0 (API 26) — нижняя граница, под
        // которую собирается Rust-часть (cargo ndk -P 26).
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.4.0"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Своего ключа пока нет: релиз подписывается отладочным, чтобы
            // его можно было поставить на телефон.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

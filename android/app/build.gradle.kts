import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Ключ подписи релизов лежит вне репозитория: кто держит ключ, тот может
// выпускать обновления, которые телефоны примут за наши. Путь можно
// переопределить через NET_SURGEON_SIGNING. Файла нет (сборка из исходников
// у другого человека) — релиз подписывается отладочным ключом, как раньше.
val signingFile = file(
    System.getenv("NET_SURGEON_SIGNING")
        ?: "${System.getProperty("user.home")}/.config/net_surgeon/signing.properties"
)
val signing = Properties().apply {
    if (signingFile.exists()) signingFile.inputStream().use { load(it) }
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
        versionCode = 19
        versionName = "0.6.3"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        if (!signing.isEmpty) {
            create("release") {
                storeFile = file(signing.getProperty("storeFile"))
                storePassword = signing.getProperty("storePassword")
                keyAlias = signing.getProperty("keyAlias")
                keyPassword = signing.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // R8 выбрасывает неиспользуемую стандартную библиотеку Kotlin:
            // classes.dex с 2 МБ до сотни КБ. Имена методов для JNI правила
            // по умолчанию сохраняют сами (-keepclasseswithmembernames native).
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            signingConfig = signingConfigs.findByName("release")
                ?: signingConfigs.getByName("debug")
        }
    }

    // Ядро на Rust — 6 МБ из 6. Без сжатия Android грузит его прямо из APK,
    // но и качать приходится все 6 МБ, а раздаём мы с GitHub, где никто
    // не сожмёт за нас. Сжатое оно ~2,5 МБ; платим распаковкой при установке
    // (доля секунды) и ~3 МБ на телефоне — на скорость запуска это не влияет.
    packaging {
        jniLibs {
            useLegacyPackaging = true
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

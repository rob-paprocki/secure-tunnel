plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.securetunnel.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.securetunnel.app"
        minSdk = 26
        targetSdk = 36
        // packaging/android/build-android.py passes the version from Cargo.toml.
        versionName = System.getenv("ST_VERSION_NAME") ?: "1.0.0"
        versionCode = System.getenv("ST_VERSION_CODE")?.toInt() ?: 10000
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // Release builds use the key named by ST_KEYSTORE (its password in
    // ST_KEYSTORE_PASSWORD), as packaging/android/build-android.py sets them.
    // Without them, release builds fall back to the debug key, which is fine
    // for trying a build but can't update an installed release.
    val releaseKeystore = System.getenv("ST_KEYSTORE")?.let { file(it) }?.takeIf { it.isFile }
    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = System.getenv("ST_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ST_KEY_ALIAS") ?: "securetunnel"
                keyPassword = System.getenv("ST_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // R8 shrinks the Compose libraries; proguard-rules.pro keeps what the Rust core calls by name.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.08.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.core:core-ktx:1.16.0")
}

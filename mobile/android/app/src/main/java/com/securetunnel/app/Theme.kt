package com.securetunnel.app

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

/** The shield blue from the app icon, and the desktop app's "connected" green. */
val Brand = Color(0xFF2B6CD6)
val ConnectedGreen = Color(0xFF0A8A0A)

private val Light = lightColorScheme(primary = Brand, secondary = Color(0xFF4A5F80), tertiary = ConnectedGreen)
private val Dark = darkColorScheme(primary = Color(0xFF8FB4FF), secondary = Color(0xFFB4C6E6), tertiary = Color(0xFF6FD66F))

/** Theme setting values stored in Profiles' settings. */
object ThemeMode {
    const val SYSTEM = "system"
    const val LIGHT = "light"
    const val DARK = "dark"
}

@Composable
fun SecureTunnelTheme(mode: String, dynamicColor: Boolean, content: @Composable () -> Unit) {
    val dark = when (mode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
        else -> isSystemInDarkTheme()
    }
    val ctx = LocalContext.current
    val scheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> Dark
        else -> Light
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

@file:OptIn(ExperimentalMaterial3Api::class)

package com.securetunnel.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private val THEMES = listOf(ThemeMode.SYSTEM to "System", ThemeMode.LIGHT to "Light", ThemeMode.DARK to "Dark")

@Composable
fun SettingsScreen(activity: MainActivity, back: () -> Unit) {
    val version = runCatching { activity.packageManager.getPackageInfo(activity.packageName, 0).versionName }.getOrNull() ?: "?"
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Group("Appearance") {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    THEMES.forEachIndexed { i, (key, label) ->
                        SegmentedButton(
                            selected = activity.themeMode == key,
                            onClick = { activity.setTheme(key) },
                            shape = SegmentedButtonDefaults.itemShape(index = i, count = THEMES.size),
                        ) { Text(label) }
                    }
                }
                if (Build.VERSION.SDK_INT >= 31) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text("Use wallpaper colours", style = MaterialTheme.typography.bodyLarge)
                            Text("Material You colours instead of the app's blue", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Switch(checked = activity.dynamicColor, onCheckedChange = { activity.setDynamic(it) })
                    }
                }
            }

            Group("Split tunnelling") {
                var excludeAuto by remember { mutableStateOf(TunnelService.excludeAndroidAuto(activity)) }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Leave Android Auto out of the VPN", style = MaterialTheme.typography.bodyLarge)
                        Text(
                            "For every profile, unless a profile lists only specific apps. Takes effect on the next connect.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = excludeAuto, onCheckedChange = {
                        excludeAuto = it
                        Profiles.setSetting(activity, "exclude_android_auto", if (it) "1" else "0")
                    })
                }
            }

            Group("Kill switch and auto-connect") {
                Body(
                    "On Android, the kill switch is part of the system's VPN settings. Turn on Always-on VPN for Secure Tunnel to " +
                        "connect automatically when the phone starts, and Block connections without VPN so nothing gets out if the " +
                        "tunnel drops. Always-on connects to the profile selected on the main screen."
                )
                val running = TunnelService.state != TunnelService.State.DISCONNECTED
                if (running && Build.VERSION.SDK_INT >= 29) {
                    Body("Always-on VPN: ${if (TunnelService.alwaysOn) "on" else "off"}\nBlock connections without VPN: ${if (TunnelService.lockdown) "on" else "off"}")
                } else {
                    Body("Connect once to see whether they're on.")
                }
                Button(onClick = { activity.startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }) {
                    Text("Open Android VPN settings")
                }
            }

            Group("About") {
                Body("Secure Tunnel $version")
                Body("A WireGuard and AmneziaWG client that can disguise its traffic. Free software under the GNU GPL, version 3 or later.")
                Body("Built with boringtun (BSD-3-Clause) and Jetpack Compose (Apache-2.0).")
                OutlinedButton(onClick = {
                    activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/rob-paprocki/secure-tunnel")))
                }) { Text("Project page") }
            }
        }
    }
}

@Composable
private fun Group(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun Body(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

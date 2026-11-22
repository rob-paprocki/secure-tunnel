package com.securetunnel.app

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

/** Where the app is: a simple back stack of screens. */
sealed interface Screen {
    data object Home : Screen
    /** Edits a saved profile, or a new one when [name] is null. */
    data class Editor(val name: String?) : Screen
    data object Apps : Screen
    data object Logs : Screen
    data object Settings : Screen
}

class MainActivity : ComponentActivity() {
    /** Bumped whenever the saved profiles change, so lists reload. */
    var profilesVersion by mutableIntStateOf(0)
    var message by mutableStateOf<String?>(null)
    var themeMode by mutableStateOf(ThemeMode.SYSTEM)
    var dynamicColor by mutableStateOf(false)

    private var pendingProfile: String? = null

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val name = pendingProfile
        pendingProfile = null
        if (r.resultCode == RESULT_OK && name != null) startTunnel(name)
        else if (name != null) message = "Android needs your permission to start the VPN."
    }

    private val picker = registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        uris.forEach { importUri(it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        themeMode = Profiles.setting(this, "theme", ThemeMode.SYSTEM)
        dynamicColor = Profiles.setting(this, "dynamic_color", "0") == "1"
        handleIncoming(intent)
        setContent {
            SecureTunnelTheme(themeMode, dynamicColor) { App(this) }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncoming(intent)
    }

    fun pickFiles() = picker.launch(arrayOf("*/*"))

    fun connect(name: String) {
        Profiles.setActive(this, name)
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingProfile = name
            vpnConsent.launch(consent)
        } else {
            startTunnel(name)
        }
    }

    fun disconnect() {
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_DISCONNECT))
    }

    private fun startTunnel(name: String) {
        startService(Intent(this, TunnelService::class.java).setAction(TunnelService.ACTION_CONNECT).putExtra("profile", name))
    }

    fun setTheme(mode: String) {
        themeMode = mode
        Profiles.setSetting(this, "theme", mode)
    }

    fun setDynamic(on: Boolean) {
        dynamicColor = on
        Profiles.setSetting(this, "dynamic_color", if (on) "1" else "0")
    }

    private fun handleIncoming(intent: Intent?) {
        intent ?: return
        val uri: Uri? = when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> if (android.os.Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
            else -> null
        }
        if (uri != null) importUri(uri)
    }

    private fun displayName(uri: Uri): String {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) return c.getString(0) ?: ""
        }
        return uri.lastPathSegment ?: ""
    }

    private fun importUri(uri: Uri) {
        try {
            val text = contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
                ?: throw IllegalArgumentException("Could not read the file.")
            if (text.length > 64 * 1024) throw IllegalArgumentException("That file is too large to be a WireGuard profile.")
            Core.fields(text) // throws if the shared parser rejects it
            val name = Profiles.save(this, displayName(uri).removeSuffix(".conf").ifBlank { "Profile" }, text)
            profilesVersion++
            message = "Imported \"$name\"."
        } catch (e: Exception) {
            message = "Could not import that profile: ${e.message}"
        }
    }
}

@Composable
fun App(activity: MainActivity) {
    var stack by remember { mutableStateOf(listOf<Screen>(Screen.Home)) }
    val editor = remember { mutableStateOf<EditorState?>(null) }
    val go: (Screen) -> Unit = { s ->
        if (s is Screen.Editor) editor.value = EditorState.open(activity, s.name)
        stack = stack + s
    }
    val back: () -> Unit = { if (stack.size > 1) stack = stack.dropLast(1) }
    BackHandler(enabled = stack.size > 1) { back() }

    when (val s = stack.last()) {
        Screen.Home -> HomeScreen(activity, go)
        is Screen.Editor -> editor.value?.let { EditorScreen(activity, it, go, back) }
        Screen.Apps -> editor.value?.let { AppsScreen(it, back) }
        Screen.Logs -> LogsScreen(back)
        Screen.Settings -> SettingsScreen(activity, back)
    }

    activity.message?.let { msg ->
        AlertDialog(
            onDismissRequest = { activity.message = null },
            confirmButton = { TextButton(onClick = { activity.message = null }) { Text("OK") } },
            text = { Text(msg) },
        )
    }
}

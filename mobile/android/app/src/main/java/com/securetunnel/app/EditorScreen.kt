@file:OptIn(ExperimentalMaterial3Api::class)

package com.securetunnel.app

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

/** The profile being edited; shared with the app picker. */
class EditorState(val originalName: String?, val originalText: String, form: ProfileForm, name: String) {
    var name by mutableStateOf(name)
    val fields = mutableStateMapOf<String, String>().apply { putAll(form.fields) }
    val problems = mutableStateListOf<Problem>().apply { addAll(form.problems) }

    operator fun get(key: String): String = fields[key].orEmpty()
    operator fun set(key: String, value: String) {
        fields[key] = value
        problems.removeAll { it.field == key }
    }

    /** "all", "only" (AllowedApps) or "except" (DisallowedApps), as Android's VPN can use one list at a time. */
    val appMode: String
        get() = when {
            Core.splitList(this["AllowedApps"]).isNotEmpty() -> "only"
            Core.splitList(this["DisallowedApps"]).isNotEmpty() -> "except"
            else -> "all"
        }

    companion object {
        fun open(ctx: Context, name: String?): EditorState {
            val text = name?.let { runCatching { Profiles.read(ctx, it) }.getOrDefault("") } ?: ""
            val form = runCatching { Core.fields(text) }.getOrElse { Core.fields("") }
            val state = EditorState(name, text, form, name ?: "")
            if (name == null) {
                // New profiles start with their own key pair and full-tunnel routing.
                val (priv, _) = Core.keypair()
                state.fields["PrivateKey"] = priv
                state.fields["AllowedIPs"] = "0.0.0.0/0, ::/0"
                state.fields["PersistentKeepalive"] = "25"
            }
            return state
        }

        val REQUIRED = listOf("PrivateKey" to "Private key", "Address" to "Address", "PublicKey" to "Server public key", "Endpoint" to "Endpoint", "AllowedIPs" to "Tunneled networks")
    }
}

@Composable
fun EditorScreen(activity: MainActivity, st: EditorState, go: (Screen) -> Unit, back: () -> Unit) {
    var nameError by remember { mutableStateOf<String?>(null) }
    var savedNotice by remember { mutableStateOf<String?>(null) }

    fun save() {
        nameError = null
        if (st.name.isBlank()) { nameError = "Give the profile a name."; return }
        val missing = EditorState.REQUIRED.filter { (k, _) -> st[k].isBlank() }
        if (missing.isNotEmpty()) {
            st.problems.clear()
            missing.forEach { (k, label) -> st.problems.add(Problem(k, "$label is required.")) }
            return
        }
        val saved = try {
            Core.update(st.originalText, st.fields.toMap())
        } catch (e: Exception) {
            activity.message = "Could not save: ${e.message}"
            return
        }
        st.problems.clear()
        st.problems.addAll(saved.problems)
        if (saved.problems.isNotEmpty()) return
        try {
            val final = if (st.originalName == null) {
                Profiles.save(activity, st.name.trim(), saved.text)
            } else {
                Profiles.write(activity, st.originalName, saved.text)
                if (st.name.trim() != st.originalName) Profiles.rename(activity, st.originalName, st.name.trim()) else st.originalName
            }
            activity.profilesVersion++
            val live = TunnelService.state == TunnelService.State.CONNECTED && TunnelService.profile == st.originalName
            if (live) savedNotice = final else back()
        } catch (e: Exception) {
            activity.message = "Could not save: ${e.message}"
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (st.originalName == null) "New profile" else "Edit profile") },
                navigationIcon = { IconButton(onClick = back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
                actions = { TextButton(onClick = { save() }) { Text("Save") } },
            )
        },
    ) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (st.problems.isNotEmpty()) {
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                    Column(Modifier.padding(12.dp)) {
                        Text("Fix these before saving:", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer)
                        st.problems.forEach { Text("• ${it.message}", color = MaterialTheme.colorScheme.onErrorContainer) }
                    }
                }
            }
            OutlinedTextField(
                value = st.name, onValueChange = { st.name = it; nameError = null },
                label = { Text("Profile name") }, singleLine = true, isError = nameError != null,
                supportingText = nameError?.let { { Text(it) } }, modifier = Modifier.fillMaxWidth(),
            )

            Section("Interface (this phone)", initiallyOpen = true) {
                KeyField(st)
                Field(st, "Address", "Address", "e.g. 192.168.100.2/32, fd00::2/128")
                Field(st, "DNS", "DNS servers", "e.g. 1.1.1.1, comma separated")
                Field(st, "MTU", "MTU", "automatic · 576 to 65535", KeyboardType.Number)
                Field(st, "ListenPort", "Listen port", "random · 1 to 65535", KeyboardType.Number)
            }

            Section("Peer (server)", initiallyOpen = true) {
                Field(st, "PublicKey", "Server public key", "base64, 44 characters", mono = true)
                Field(st, "PresharedKey", "Preshared key", "optional; must match the server", secret = true, mono = true)
                Field(st, "Endpoint", "Endpoint", "vpn.example.com:51820", KeyboardType.Uri)
                Field(st, "AllowedIPs", "Tunneled networks (AllowedIPs)", "0.0.0.0/0, ::/0 sends everything")
                Field(st, "PersistentKeepalive", "Persistent keep-alive (seconds)", "e.g. 25", KeyboardType.Number)
            }

            Section("Split tunnelling", initiallyOpen = true) {
                val only = Core.splitList(st["AllowedApps"]).size
                val except = Core.splitList(st["DisallowedApps"]).size
                val summary = when (st.appMode) {
                    "only" -> "Only $only app${if (only == 1) "" else "s"} use the VPN"
                    "except" -> "All apps except $except use the VPN"
                    else -> "All apps use the VPN"
                }
                Row(
                    Modifier.fillMaxWidth().clickable { go(Screen.Apps) }.padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Apps", style = MaterialTheme.typography.bodyLarge)
                        Text(summary, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = "Choose apps")
                }
                HorizontalDivider()
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Bypass LAN traffic", style = MaterialTheme.typography.bodyLarge)
                        Text("Reach printers and other local devices directly", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = st["BypassLanTraffic"].equals("true", ignoreCase = true), onCheckedChange = { st["BypassLanTraffic"] = if (it) "true" else "" })
                }
                Field(st, "DisallowedIPs", "Non-tunneled networks", "addresses that skip the VPN, e.g. 192.0.2.0/24")
            }

            Section("Junk packets") {
                Note("Random packets sent just before each handshake, so the start of the connection doesn't look like WireGuard. Works with any WireGuard server: it ignores them.")
                FieldPair(st, "Jc", "Jc · how many", "0–128, e.g. 4", "Jd", "Jd · delay (ms)", "0–200")
                FieldPair(st, "Jmin", "Jmin · min size", "0–1280, e.g. 40", "Jmax", "Jmax · max size", "0–1280, e.g. 70")
                Note("I1–I5 are optional packets built from a pattern (AmneziaWG 1.5 style), also sent before each handshake.")
                for (i in 1..5) Field(st, "I$i", "I$i · packet $i", "optional pattern, e.g. <r 32>", mono = true)
            }

            Section("Protocol masking") {
                Note("Sends one packet that looks like QUIC, DNS, SIP or STUN traffic to a domain before every handshake. Works with any WireGuard server.")
                Field(st, "Id", "Masking domain (Id)", "e.g. a popular site in your region", KeyboardType.Uri)
                Choice(st, "Ip", "Masking protocol (Ip)", listOf("quic", "dns", "sip", "stun"))
                Choice(st, "Ib", "Browser (Ib)", listOf("chrome", "firefox", "cURL", "random"))
            }

            Section("AmneziaWG headers") {
                Note("Padding and header values that change every packet. Only use these if your server runs AmneziaWG with exactly the same values; with a standard WireGuard server, leave them empty or the connection won't work.")
                FieldPair(st, "S1", "S1 · init padding", "", "S2", "S2 · response padding", "")
                FieldPair(st, "S3", "S3 · cookie padding", "", "S4", "S4 · transport padding", "")
                FieldPair(st, "H1", "H1 · init header", "number or min-max", "H2", "H2 · response header", "")
                FieldPair(st, "H3", "H3 · cookie header", "", "H4", "H4 · transport header", "")
            }

            Section("SOCKS5 proxy") {
                Note("Sends the VPN's traffic through a SOCKS5 proxy (UDP relay) if a direct connection is blocked.")
                Field(st, "Socks5Proxy", "SOCKS5 proxy", "host:1080", KeyboardType.Uri)
                Field(st, "Socks5ProxyUsername", "Username", "optional")
                Field(st, "Socks5ProxyPassword", "Password", "optional", secret = true)
            }
            Spacer(Modifier.height(24.dp))
            Button(onClick = { save() }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
            Spacer(Modifier.height(32.dp))
        }
    }

    savedNotice?.let { name ->
        AlertDialog(
            onDismissRequest = { savedNotice = null; back() },
            title = { Text("Saved") },
            text = { Text("Reconnect to use the changes now?") },
            confirmButton = { TextButton(onClick = { savedNotice = null; activity.connect(name); back() }) { Text("Reconnect") } },
            dismissButton = { TextButton(onClick = { savedNotice = null; back() }) { Text("Later") } },
        )
    }
}

@Composable
private fun Section(title: String, initiallyOpen: Boolean = false, content: @Composable () -> Unit) {
    var open by remember { mutableStateOf(initiallyOpen) }
    Card(Modifier.fillMaxWidth()) {
        Column {
            Row(
                Modifier.fillMaxWidth().clickable { open = !open }.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                Icon(if (open) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown, contentDescription = if (open) "Collapse" else "Expand")
            }
            AnimatedVisibility(open) {
                Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { content() }
            }
        }
    }
}

@Composable
private fun Note(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Field(
    st: EditorState,
    key: String,
    label: String,
    hint: String,
    keyboard: KeyboardType = KeyboardType.Text,
    secret: Boolean = false,
    mono: Boolean = false,
    modifier: Modifier = Modifier.fillMaxWidth(),
) {
    val problem = st.problems.firstOrNull { it.field == key }
    var shown by remember { mutableStateOf(!secret) }
    OutlinedTextField(
        value = st[key],
        onValueChange = { st[key] = it },
        label = { Text(label) },
        placeholder = if (hint.isNotEmpty()) ({ Text(hint) }) else null,
        singleLine = true,
        isError = problem != null,
        supportingText = problem?.let { { Text(it.message) } },
        keyboardOptions = KeyboardOptions(keyboardType = if (secret) KeyboardType.Password else keyboard),
        visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge,
        trailingIcon = if (secret) ({
            IconButton(onClick = { shown = !shown }) { Icon(Icons.Filled.Lock, contentDescription = if (shown) "Hide" else "Show") }
        }) else null,
        modifier = modifier,
    )
}

@Composable
private fun FieldPair(st: EditorState, k1: String, l1: String, h1: String, k2: String, l2: String, h2: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Field(st, k1, l1, h1, KeyboardType.Text, modifier = Modifier.weight(1f))
        Field(st, k2, l2, h2, KeyboardType.Text, modifier = Modifier.weight(1f))
    }
}

/** The private key, with a generator and this phone's public key to give the server. */
@Composable
private fun KeyField(st: EditorState) {
    val ctx = LocalContext.current
    val publicKey = remember(st["PrivateKey"]) {
        runCatching { Core.fields(Core.update("", mapOf("PrivateKey" to st["PrivateKey"])).text).ownPublicKey }.getOrDefault("")
    }
    var confirm by remember { mutableStateOf(false) }
    Field(st, "PrivateKey", "Private key", "base64, 44 characters", secret = true, mono = true)
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(onClick = { if (st["PrivateKey"].isBlank()) st["PrivateKey"] = Core.keypair().first else confirm = true }) {
            Icon(Icons.Filled.Refresh, contentDescription = null)
            Text("  New key pair")
        }
    }
    if (publicKey.isNotEmpty()) {
        Column {
            Text("This phone's public key (add it to the server):", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(publicKey, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                TextButton(onClick = { copyText(ctx, "Public key", publicKey) }) { Text("Copy") }
            }
        }
    }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Replace the key?") },
            text = { Text("The server only knows the current key. After replacing it you must add the new public key to the server, or this profile stops working.") },
            confirmButton = { TextButton(onClick = { st["PrivateKey"] = Core.keypair().first; confirm = false }) { Text("Replace") } },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun Choice(st: EditorState, key: String, label: String, options: List<String>) {
    var open by remember { mutableStateOf(false) }
    val problem = st.problems.firstOrNull { it.field == key }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }) {
        OutlinedTextField(
            value = st[key].ifEmpty { "none" },
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            isError = problem != null,
            supportingText = problem?.let { { Text(it.message) } },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            (listOf("") + options).forEach { v ->
                DropdownMenuItem(text = { Text(v.ifEmpty { "none" }) }, onClick = { st[key] = v; open = false })
            }
        }
    }
}

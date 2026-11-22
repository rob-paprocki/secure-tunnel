@file:OptIn(ExperimentalMaterial3Api::class)

package com.securetunnel.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

/** What the screen shows about the tunnel, refreshed once a second. */
data class TunnelView(
    val state: TunnelService.State = TunnelService.State.DISCONNECTED,
    val profile: String = "",
    val server: String = "",
    val protection: String = "",
    val error: String = "",
    val stats: Stats? = null,
    val txRate: Long = 0,
    val rxRate: Long = 0,
)

private data class ProfileRow(val name: String, val endpoint: String)

@Composable
fun HomeScreen(activity: MainActivity, go: (Screen) -> Unit) {
    var view by remember { mutableStateOf(TunnelView()) }
    LaunchedEffect(Unit) {
        var last: Stats? = null
        while (true) {
            val stats = Core.stats(TunnelService.handle)
            val prev = last
            view = TunnelView(
                state = TunnelService.state,
                profile = TunnelService.profile,
                server = TunnelService.server,
                protection = TunnelService.protection,
                error = TunnelService.error,
                stats = stats,
                txRate = if (stats != null && prev != null) maxOf(0, stats.tx - prev.tx) else 0,
                rxRate = if (stats != null && prev != null) maxOf(0, stats.rx - prev.rx) else 0,
            )
            last = stats
            delay(1000)
        }
    }
    val rows = remember(activity.profilesVersion) {
        Profiles.names(activity).map { n ->
            val endpoint = runCatching { Core.fields(Profiles.read(activity, n)).fields["Endpoint"].orEmpty() }.getOrDefault("")
            ProfileRow(n, endpoint)
        }
    }
    var active by remember(activity.profilesVersion) { mutableStateOf(Profiles.active(activity)) }
    var addMenu by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Secure Tunnel") },
                actions = {
                    IconButton(onClick = { go(Screen.Logs) }) { Icon(Icons.AutoMirrored.Filled.List, contentDescription = "Logs") }
                    IconButton(onClick = { go(Screen.Settings) }) { Icon(Icons.Filled.Settings, contentDescription = "Settings") }
                },
            )
        },
        floatingActionButton = {
            Box {
                ExtendedFloatingActionButton(
                    onClick = { addMenu = true },
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text("Add profile") },
                )
                DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }) {
                    DropdownMenuItem(text = { Text("Import .conf file") }, onClick = { addMenu = false; activity.pickFiles() })
                    DropdownMenuItem(text = { Text("Create new profile") }, onClick = { addMenu = false; go(Screen.Editor(null)) })
                }
            }
        },
    ) { pad ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { StatusCard(view, active, rows.isNotEmpty(), onToggle = { on -> if (on) activity.connect(active) else activity.disconnect() }) }
            view.stats?.takeIf { view.state == TunnelService.State.CONNECTED }?.let { s -> item { StatsCard(s, view) } }
            item {
                Text("Profiles", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp))
            }
            if (rows.isEmpty()) {
                item {
                    Text(
                        "No profiles yet. Tap Add profile to import a WireGuard or AmneziaWG .conf file, or to create one.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            items(rows, key = { it.name }) { row ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable {
                        active = row.name
                        Profiles.setActive(activity, row.name)
                        if (view.state == TunnelService.State.CONNECTED && view.profile != row.name) activity.connect(row.name)
                    },
                ) {
                    Row(Modifier.padding(start = 4.dp, end = 4.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = row.name == active, onClick = null, modifier = Modifier.padding(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(row.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (row.endpoint.isNotEmpty()) {
                                Text(row.endpoint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                        }
                        IconButton(onClick = { go(Screen.Editor(row.name)) }) { Icon(Icons.Filled.Edit, contentDescription = "Edit ${row.name}") }
                        IconButton(onClick = { confirmDelete = row.name }) { Icon(Icons.Filled.Delete, contentDescription = "Delete ${row.name}") }
                    }
                }
            }
        }
    }

    confirmDelete?.let { name ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete profile") },
            text = { Text("Delete \"$name\"? Its keys are removed from this phone.") },
            confirmButton = {
                TextButton(onClick = {
                    if (view.state != TunnelService.State.DISCONNECTED && view.profile == name) activity.disconnect()
                    Profiles.delete(activity, name)
                    activity.profilesVersion++
                    confirmDelete = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun StatusCard(view: TunnelView, active: String, hasProfiles: Boolean, onToggle: (Boolean) -> Unit) {
    val on = view.state == TunnelService.State.CONNECTED || view.state == TunnelService.State.CONNECTING
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Switch(
                checked = on,
                onCheckedChange = onToggle,
                enabled = hasProfiles && view.state != TunnelService.State.DISCONNECTING,
                colors = SwitchDefaults.colors(checkedTrackColor = ConnectedGreen),
                modifier = Modifier.scale(1.8f).padding(8.dp),
            )
            Spacer(Modifier.height(20.dp))
            val title = when (view.state) {
                TunnelService.State.CONNECTED -> "Connected to ${view.profile}"
                TunnelService.State.CONNECTING -> "Connecting to ${view.profile}…"
                TunnelService.State.DISCONNECTING -> "Disconnecting…"
                TunnelService.State.DISCONNECTED -> if (hasProfiles) "Not connected" else "No profile"
            }
            Text(title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
            val sub = when {
                view.state == TunnelService.State.CONNECTED && view.server.isNotEmpty() ->
                    view.server + if (view.stats?.handshakeSecs != null) " · handshake received" else " · waiting for handshake"
                view.state == TunnelService.State.DISCONNECTED && active.isNotEmpty() -> "Tap the switch to connect to $active"
                else -> ""
            }
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
            if (view.protection.isNotEmpty() && view.state == TunnelService.State.CONNECTED) {
                Text("Protection: ${view.protection}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
            }
            if (view.error.isNotEmpty() && view.state == TunnelService.State.DISCONNECTED) {
                Spacer(Modifier.height(8.dp))
                Text(view.error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun StatsCard(s: Stats, view: TunnelView) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            StatRow("Uptime", formatDuration(s.uptimeSecs), "Ping", s.rttMs?.let { "$it ms" } ?: "–")
            StatRow("Send", formatRate(view.txRate), "Total sent", formatBytes(s.tx))
            StatRow("Receive", formatRate(view.rxRate), "Total received", formatBytes(s.rx))
            StatRow("Packet loss", "%.0f %%".format(s.loss * 100), "Handshake", s.handshakeSecs?.let { "${it}s ago" } ?: "–")
        }
    }
}

@Composable
private fun StatRow(l1: String, v1: String, l2: String, v2: String) {
    Row(Modifier.fillMaxWidth()) {
        Column(Modifier.weight(1f)) {
            Text(l1, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(v1, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(l2, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(v2, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
        }
    }
}

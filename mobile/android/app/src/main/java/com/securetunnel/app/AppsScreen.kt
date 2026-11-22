@file:OptIn(ExperimentalMaterial3Api::class)

package com.securetunnel.app

import android.Manifest
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class AppInfo(val pkg: String, val label: String, val system: Boolean, val info: ApplicationInfo)

private val MODES = listOf("all" to "All apps", "only" to "Only selected", "except" to "All except")

/**
 * Every installed app that can use the network, including system apps without a
 * launcher icon (Android Auto, for example). System apps are hidden unless asked
 * for, but a search always covers them.
 */
private fun loadApps(pm: PackageManager, own: String): List<AppInfo> {
    val pkgs = if (android.os.Build.VERSION.SDK_INT >= 33) {
        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
    } else {
        @Suppress("DEPRECATION") pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    }
    return pkgs.asSequence()
        .filter { it.packageName != own }
        .filter { it.requestedPermissions?.contains(Manifest.permission.INTERNET) == true }
        .mapNotNull { pi ->
            val ai = pi.applicationInfo ?: return@mapNotNull null
            val system = ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            AppInfo(pi.packageName, pm.getApplicationLabel(ai).toString(), system, ai)
        }
        .sortedBy { it.label.lowercase() }
        .toList()
}

@Composable
fun AppsScreen(st: EditorState, back: () -> Unit) {
    val ctx = LocalContext.current
    var mode by remember { mutableStateOf(st.appMode) }
    val selected = remember {
        mutableStateListOf<String>().apply {
            addAll(Core.splitList(st[if (st.appMode == "except") "DisallowedApps" else "AllowedApps"]))
        }
    }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    val apps by produceState<List<AppInfo>?>(initialValue = null) {
        value = withContext(Dispatchers.IO) { loadApps(ctx.packageManager, ctx.packageName) }
    }

    // Writes the choice back to the profile: one list or the other, never both.
    fun commit() {
        val list = selected.joinToString(", ")
        when (mode) {
            "only" -> { st["AllowedApps"] = list; st["DisallowedApps"] = "" }
            "except" -> { st["DisallowedApps"] = list; st["AllowedApps"] = "" }
            else -> { st["AllowedApps"] = ""; st["DisallowedApps"] = "" }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Split tunnelling") },
                navigationIcon = { IconButton(onClick = { commit(); back() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Done") } },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                MODES.forEachIndexed { i, (key, label) ->
                    SegmentedButton(
                        selected = mode == key,
                        onClick = { mode = key; commit() },
                        shape = SegmentedButtonDefaults.itemShape(index = i, count = MODES.size),
                    ) { Text(label, maxLines = 1) }
                }
            }
            Text(
                when (mode) {
                    "only" -> "Only the apps you tick go through the VPN. Everything else uses your normal connection."
                    "except" -> "Every app goes through the VPN except the ones you tick."
                    else -> "Every app goes through the VPN."
                } + if (mode != "only" && TunnelService.excludeAndroidAuto(ctx)) " Android Auto is always left out (see Settings)." else "",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            if (mode != "all") {
                OutlinedTextField(
                    value = query, onValueChange = { query = it },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    placeholder = { Text("Search all apps") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 12.dp),
                )
                Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("Show system apps", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Switch(checked = showSystem, onCheckedChange = { showSystem = it })
                }
                val list = apps
                if (list == null) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                } else {
                    val q = query.trim().lowercase()
                    val shown = list
                        .filter { a ->
                            if (q.isNotEmpty()) a.label.lowercase().contains(q) || a.pkg.contains(q)
                            else showSystem || !a.system || a.pkg in selected
                        }
                        .sortedByDescending { it.pkg in selected }
                    LazyColumn {
                        items(shown, key = { it.pkg }) { app ->
                            AppRow(app, checked = app.pkg in selected) {
                                if (app.pkg in selected) selected.remove(app.pkg) else selected.add(app.pkg)
                                commit()
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppRow(app: AppInfo, checked: Boolean, onToggle: () -> Unit) {
    val ctx = LocalContext.current
    // Icons load per row, so a long list of system apps stays quick.
    val icon by produceState<ImageBitmap?>(initialValue = null, app.pkg) {
        value = withContext(Dispatchers.IO) {
            runCatching { ctx.packageManager.getApplicationIcon(app.info).toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val bmp = icon
        if (bmp != null) Image(bmp, contentDescription = null, modifier = Modifier.size(40.dp)) else Spacer(Modifier.size(40.dp))
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(app.label, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                if (app.system) "${app.pkg} · system" else app.pkg,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Checkbox(checked = checked, onCheckedChange = null)
    }
}

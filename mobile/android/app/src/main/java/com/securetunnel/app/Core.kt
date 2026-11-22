package com.securetunnel.app

import org.json.JSONObject

/** A field the shared profile checker (src/profile.rs) objects to. */
data class Problem(val field: String, val message: String)

/** A profile split into editable fields, read by the shared Rust parser. */
data class ProfileForm(val fields: Map<String, String>, val problems: List<Problem>, val ownPublicKey: String)

data class Saved(val text: String, val problems: List<Problem>)

data class Stats(
    val connected: Boolean,
    val handshakeSecs: Long?,
    val tx: Long,
    val rx: Long,
    val loss: Double,
    val rttMs: Long?,
    val uptimeSecs: Long,
    val errors: List<String>,
)

/** Kotlin view of [TunnelCore]: typed results instead of JSON strings. */
object Core {
    private fun unwrap(json: String): JSONObject {
        val r = JSONObject(json)
        if (!r.optBoolean("ok")) throw IllegalArgumentException(r.optString("error", "Unknown error"))
        return r.getJSONObject("value")
    }

    private fun problems(o: JSONObject): List<Problem> {
        val a = o.optJSONArray("problems") ?: return emptyList()
        return (0 until a.length()).map { a.getJSONObject(it) }.map { Problem(it.getString("field"), it.getString("message")) }
    }

    fun fields(text: String): ProfileForm {
        val v = unwrap(TunnelCore.profileFields(text))
        val f = v.getJSONObject("fields")
        val map = f.keys().asSequence().associateWith { f.getString(it) }
        return ProfileForm(map, problems(v), v.optString("own_public_key"))
    }

    fun update(text: String, changes: Map<String, String>): Saved {
        val v = unwrap(TunnelCore.profileUpdate(text, JSONObject(changes).toString()))
        return Saved(v.getString("text"), problems(v))
    }

    fun keypair(): Pair<String, String> {
        val o = JSONObject(TunnelCore.generateKeypair())
        return o.getString("private") to o.getString("public")
    }

    fun stats(handle: Long): Stats? {
        if (handle == 0L) return null
        val o = JSONObject(TunnelCore.stats(handle))
        if (!o.has("connected")) return null
        val errs = o.optJSONArray("errors")
        return Stats(
            connected = o.optBoolean("connected"),
            handshakeSecs = if (o.isNull("handshake_secs")) null else o.optLong("handshake_secs"),
            tx = o.optLong("tx"),
            rx = o.optLong("rx"),
            loss = o.optDouble("loss", 0.0),
            rttMs = if (o.isNull("rtt_ms")) null else o.optLong("rtt_ms"),
            uptimeSecs = o.optLong("uptime_secs"),
            errors = if (errs == null) emptyList() else (0 until errs.length()).map { errs.getString(it) },
        )
    }

    /** Reads `AllowedApps` / `DisallowedApps`: comma-separated package names. */
    fun splitList(s: String): List<String> = s.split(',').map { it.trim() }.filter { it.isNotEmpty() }
}

fun copyText(ctx: android.content.Context, label: String, text: String) {
    val cm = ctx.getSystemService(android.content.ClipboardManager::class.java)
    cm?.setPrimaryClip(android.content.ClipData.newPlainText(label, text))
}

fun formatBytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.2f GB".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f MB".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "%.0f KB".format(n / (1L shl 10).toDouble())
    else -> "$n B"
}

fun formatRate(bytesPerSec: Long): String = when {
    bytesPerSec * 8 >= 1_000_000 -> "%.1f Mbps".format(bytesPerSec * 8 / 1_000_000.0)
    bytesPerSec * 8 >= 1_000 -> "%.0f kbps".format(bytesPerSec * 8 / 1_000.0)
    else -> "${bytesPerSec * 8} bps"
}

fun formatDuration(secs: Long): String = "%02d:%02d:%02d".format(secs / 3600, secs / 60 % 60, secs % 60)

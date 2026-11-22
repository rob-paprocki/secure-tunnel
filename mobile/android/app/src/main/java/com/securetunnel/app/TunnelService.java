package com.securetunnel.app;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Creates the VPN adapter from the profile's plan (addresses, DNS, routes,
 * per-app lists) and hands it to the shared tunnel core, which runs
 * WireGuard / AmneziaWG with the profile's junk packets and masking.
 */
public class TunnelService extends VpnService {
    static final String ACTION_CONNECT = "com.securetunnel.app.CONNECT";
    static final String ACTION_DISCONNECT = "com.securetunnel.app.DISCONNECT";

    public enum State { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING }

    // Read by the screen (same process).
    static volatile State state = State.DISCONNECTED;
    static volatile String profile = "";
    static volatile String server = "";
    static volatile String protection = "";
    static volatile String error = "";
    static volatile long handle = 0;
    /** Android's "Always-on VPN" and "Block connections without VPN", read while the service runs. */
    static volatile boolean alwaysOn = false;
    static volatile boolean lockdown = false;

    private static final ArrayDeque<String> LOG = new ArrayDeque<>();

    static void log(String message) {
        String line = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + message;
        synchronized (LOG) {
            LOG.addLast(line);
            while (LOG.size() > 300) LOG.removeFirst();
        }
    }

    static List<String> logLines() {
        synchronized (LOG) {
            return new ArrayList<>(LOG);
        }
    }

    static void clearLog() {
        synchronized (LOG) {
            LOG.clear();
        }
    }

    private ParcelFileDescriptor adapter;
    private Thread worker;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_CONNECT : intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
            disconnect();
            stopSelf();
            return START_NOT_STICKY;
        }
        // Started by the user, or by Android's Always-on VPN (no extras).
        String name = intent != null && intent.hasExtra("profile") ? intent.getStringExtra("profile") : Profiles.active(this);
        connect(name);
        return START_STICKY;
    }

    private synchronized void connect(String name) {
        if (state == State.CONNECTING || state == State.CONNECTED) disconnect();
        state = State.CONNECTING;
        profile = name;
        error = "";
        if (Build.VERSION.SDK_INT >= 29) {
            alwaysOn = isAlwaysOn();
            lockdown = isLockdownEnabled();
        }
        log("Connecting to " + name);
        worker = new Thread(() -> {
            try {
                String config = Profiles.read(this, name);
                JSONObject r = new JSONObject(TunnelCore.plan(config));
                if (!r.getBoolean("ok")) throw new Exception(r.getString("error"));
                JSONObject plan = r.getJSONObject("value");
                Builder b = new Builder().setSession(name).setMtu(plan.getInt("mtu")).setBlocking(true);
                for (String a : list(plan, "addresses")) {
                    String[] p = cidr(a);
                    b.addAddress(p[0], Integer.parseInt(p[1]));
                }
                for (String d : list(plan, "dns")) {
                    try {
                        b.addDnsServer(d);
                    } catch (IllegalArgumentException ignored) {
                        b.addSearchDomain(d);
                    }
                }
                for (String route : list(plan, "routes")) {
                    String[] p = cidr(route);
                    b.addRoute(p[0], Integer.parseInt(p[1]));
                }
                // Per-app routing: AllowedApps / DisallowedApps hold package names on Android.
                JSONArray allowed = plan.getJSONArray("allowed_apps");
                JSONArray disallowed = plan.getJSONArray("disallowed_apps");
                if (allowed.length() > 0) {
                    for (int i = 0; i < allowed.length(); i++) addApp(b, allowed.getString(i), true);
                } else {
                    boolean autoListed = false;
                    for (int i = 0; i < disallowed.length(); i++) {
                        addApp(b, disallowed.getString(i), false);
                        autoListed |= ANDROID_AUTO.equals(disallowed.getString(i));
                    }
                    // App setting (on by default): Android Auto talks to the car over the local
                    // network and Google's servers, and is usually best left off the VPN.
                    if (!autoListed && excludeAndroidAuto(this) && addApp(b, ANDROID_AUTO, false)) {
                        log("Android Auto left out of the VPN (Settings)");
                    }
                }
                adapter = b.establish();
                if (adapter == null) throw new Exception("Android did not allow the VPN. Open the app and connect again.");
                JSONObject s = new JSONObject(TunnelCore.start(this, config, adapter.getFd(), plan.getString("server"), plan.optString("proxy", "")));
                if (!s.getBoolean("ok")) throw new Exception(s.getString("error"));
                handle = s.getLong("value");
                server = plan.getString("server");
                protection = plan.optString("protection", "");
                state = State.CONNECTED;
                log("Connected to " + server + (protection.isEmpty() ? "" : " (" + protection + ")"));
            } catch (Exception e) {
                error = e.getMessage() == null ? e.toString() : e.getMessage();
                log("Connection failed: " + error);
                closeAdapter();
                state = State.DISCONNECTED;
                stopSelf();
            }
        }, "tunnel-start");
        worker.start();
    }

    static final String ANDROID_AUTO = "com.google.android.projection.gearhead";

    static boolean excludeAndroidAuto(android.content.Context c) {
        return !"0".equals(Profiles.setting(c, "exclude_android_auto", "1"));
    }

    /** Returns false when the app isn't installed on this phone. */
    private boolean addApp(Builder b, String pkg, boolean allow) {
        try {
            if (allow) b.addAllowedApplication(pkg); else b.addDisallowedApplication(pkg);
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private synchronized void disconnect() {
        if (state == State.DISCONNECTED) return;
        state = State.DISCONNECTING;
        long h = handle;
        handle = 0;
        if (h != 0) TunnelCore.stop(h);
        closeAdapter();
        state = State.DISCONNECTED;
        log("Disconnected");
    }

    private void closeAdapter() {
        if (adapter != null) {
            try {
                adapter.close();
            } catch (Exception ignored) {
            }
            adapter = null;
        }
    }

    @Override
    public void onRevoke() {
        // Another VPN took over, or the user turned this one off in Settings.
        log("Android stopped the VPN (another VPN started, or it was turned off in Settings)");
        disconnect();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        disconnect();
        super.onDestroy();
    }

    private static String[] cidr(String s) {
        String t = s.trim();
        int i = t.indexOf('/');
        if (i < 0) return new String[] {t, t.contains(":") ? "128" : "32"};
        return new String[] {t.substring(0, i), t.substring(i + 1)};
    }

    private static String[] list(JSONObject o, String key) throws Exception {
        JSONArray a = o.getJSONArray(key);
        String[] out = new String[a.length()];
        for (int i = 0; i < a.length(); i++) out[i] = a.getString(i);
        return out;
    }
}

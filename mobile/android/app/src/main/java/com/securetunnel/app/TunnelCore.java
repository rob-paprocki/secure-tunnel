package com.securetunnel.app;

import android.net.VpnService;

/** The shared Rust tunnel core (libsecuretunnel.so, built from mobile/core). */
final class TunnelCore {
    static {
        System.loadLibrary("securetunnel");
    }

    private TunnelCore() {}

    /** {"ok":true,"value":{addresses,dns,routes,mtu,server,proxy,allowed_apps,disallowed_apps,protection}} or {"ok":false,"error":..}. */
    static native String plan(String config);

    /** {"ok":true,"value":handle} or {"ok":false,"error":..}. The core protects its sockets through {@code service}. */
    static native String start(VpnService service, String config, int fd, String server, String proxy);

    /** {"connected":..,"handshake_secs":..,"tx":..,"rx":..,"loss":..,"rtt_ms":..,"uptime_secs":..,"errors":[..]} */
    static native String stats(long handle);

    static native void stop(long handle);

    /** {"ok":true,"value":{fields:{key:value},problems:[{field,message}],own_public_key}}; "" for a new profile. */
    static native String profileFields(String config);

    /** Applies a JSON object of field changes: {"ok":true,"value":{text,problems}}. */
    static native String profileUpdate(String config, String changes);

    /** {"private":..,"public":..}: a new WireGuard key pair. */
    static native String generateKeypair();
}

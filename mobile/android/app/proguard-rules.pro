# The Rust core (libsecuretunnel.so) binds to these by name over JNI.
-keep class com.securetunnel.app.TunnelCore { native <methods>; }
-keep class com.securetunnel.app.TunnelService { *; }

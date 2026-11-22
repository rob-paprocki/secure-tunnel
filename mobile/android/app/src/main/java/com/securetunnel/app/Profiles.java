package com.securetunnel.app;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** WireGuard / AmneziaWG profiles kept as .conf files in the app's private storage. */
final class Profiles {
    private Profiles() {}

    static File dir(Context c) {
        File d = new File(c.getFilesDir(), "profiles");
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        return d;
    }

    static List<String> names(Context c) {
        List<String> out = new ArrayList<>();
        File[] files = dir(c).listFiles();
        if (files != null) {
            for (File f : files) {
                String n = f.getName();
                if (n.endsWith(".conf")) out.add(n.substring(0, n.length() - 5));
            }
        }
        Collections.sort(out, String.CASE_INSENSITIVE_ORDER);
        return out;
    }

    static String read(Context c, String name) throws IOException {
        return new String(Files.readAllBytes(new File(dir(c), name + ".conf").toPath()), StandardCharsets.UTF_8);
    }

    /** Saves a profile, adding " (2)" and so on when the name is taken. Returns the name used. */
    static String save(Context c, String name, String text) throws IOException {
        String base = name.replaceAll("[\\\\/:*?\"<>|]", "_").trim();
        if (base.isEmpty()) base = "Profile";
        String n = base;
        for (int i = 2; new File(dir(c), n + ".conf").exists(); i++) n = base + " (" + i + ")";
        try (FileOutputStream o = new FileOutputStream(new File(dir(c), n + ".conf"))) {
            o.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return n;
    }

    /** Overwrites a profile's text. */
    static void write(Context c, String name, String text) throws IOException {
        try (FileOutputStream o = new FileOutputStream(new File(dir(c), name + ".conf"))) {
            o.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Renames a profile; returns the name used (made unique like {@link #save}). */
    static String rename(Context c, String from, String to) throws IOException {
        String text = read(c, from);
        boolean wasActive = from.equals(active(c));
        //noinspection ResultOfMethodCallIgnored
        new File(dir(c), from + ".conf").delete();
        String n = save(c, to, text);
        if (wasActive) setActive(c, n);
        return n;
    }

    static String setting(Context c, String key, String fallback) {
        return prefs(c).getString(key, fallback);
    }

    static void setSetting(Context c, String key, String value) {
        prefs(c).edit().putString(key, value).apply();
    }

    static void delete(Context c, String name) {
        //noinspection ResultOfMethodCallIgnored
        new File(dir(c), name + ".conf").delete();
        if (name.equals(active(c))) setActive(c, "");
    }

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("settings", Context.MODE_PRIVATE);
    }

    static String active(Context c) {
        String a = prefs(c).getString("active", "");
        if (a.isEmpty() || !names(c).contains(a)) {
            List<String> n = names(c);
            return n.isEmpty() ? "" : n.get(0);
        }
        return a;
    }

    static void setActive(Context c, String name) {
        prefs(c).edit().putString("active", name).apply();
    }
}

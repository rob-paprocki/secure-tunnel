//! C interface, used by the iOS packet tunnel extension (Swift) through
//! `include/securetunnel.h`. Strings in and out are UTF-8; strings returned by
//! the core are freed with `st_string_free`.

use std::ffi::{CStr, CString, c_char};

use crate::tunnel::{self, FdDevice, Session};

fn text(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn out(s: String) -> *mut c_char {
    CString::new(s.replace('\0', " ")).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

fn json<T: serde::Serialize>(r: Result<T, String>) -> String {
    match r {
        Ok(v) => serde_json::json!({ "ok": true, "value": v }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// Reads a profile: `{"ok":true,"value":{addresses,dns,routes,mtu,server,proxy,...}}`
/// or `{"ok":false,"error":"..."}`.
#[unsafe(no_mangle)]
pub extern "C" fn st_plan(config: *const c_char) -> *mut c_char {
    out(json(tunnel::plan(&text(config))))
}

/// Starts the tunnel on the adapter `fd`. Returns a handle, or null with the
/// reason in `*error` (free it with `st_string_free`).
#[unsafe(no_mangle)]
pub extern "C" fn st_start(
    config: *const c_char,
    fd: i32,
    utun_header: bool,
    server: *const c_char,
    proxy: *const c_char,
    error: *mut *mut c_char,
) -> *mut Session {
    match Session::start(&text(config), FdDevice::new(fd, utun_header), &text(server), &text(proxy)) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(e) => {
            if !error.is_null() {
                unsafe { *error = out(e) };
            }
            std::ptr::null_mut()
        }
    }
}

/// `{"connected":..,"tx":..,"rx":..,"loss":..,"rtt_ms":..,"uptime_secs":..}`
#[unsafe(no_mangle)]
pub extern "C" fn st_stats(session: *const Session) -> *mut c_char {
    if session.is_null() {
        return out("{}".into());
    }
    out(serde_json::to_string(&unsafe { &*session }.stats()).unwrap_or_default())
}

/// Stops the tunnel and frees the handle.
#[unsafe(no_mangle)]
pub extern "C" fn st_stop(session: *mut Session) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn st_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

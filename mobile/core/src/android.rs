//! JNI interface for the Android app (`com.securetunnel.app.TunnelCore`).
//!
//! Every socket the core opens is passed to the running `VpnService`'s
//! `protect(int)` before use, so the tunnel's own traffic goes out on the real
//! network instead of looping back into the VPN.

use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};

use crate::tunnel::{self, FdDevice, Session};

fn get(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|s| s.into()).unwrap_or_default()
}

fn put(env: &mut JNIEnv, s: String) -> jstring {
    env.new_string(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn json<T: serde::Serialize>(r: Result<T, String>) -> String {
    match r {
        Ok(v) => serde_json::json!({ "ok": true, "value": v }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
    }
}

/// Points the core's socket hook at this `VpnService.protect`.
fn hook_protect(env: &mut JNIEnv, service: &JObject) -> Result<(), String> {
    let vm: JavaVM = env.get_java_vm().map_err(|e| e.to_string())?;
    let service: GlobalRef = env.new_global_ref(service).map_err(|e| e.to_string())?;
    crate::socks::set_protect(Some(Box::new(move |fd: i64| {
        let Ok(mut env) = vm.attach_current_thread() else { return false };
        env.call_method(service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd as i32)])
            .and_then(|v| v.z())
            .unwrap_or(false)
    })));
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_plan(mut env: JNIEnv, _c: JClass, config: JString) -> jstring {
    let config = get(&mut env, &config);
    let r = json(tunnel::plan(&config));
    put(&mut env, r)
}

/// Returns `{"ok":true,"value":<handle>}` or `{"ok":false,"error":...}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_start(
    mut env: JNIEnv,
    _c: JClass,
    service: JObject,
    config: JString,
    fd: jint,
    server: JString,
    proxy: JString,
) -> jstring {
    let (config, server, proxy) = (get(&mut env, &config), get(&mut env, &server), get(&mut env, &proxy));
    let r = hook_protect(&mut env, &service)
        .and_then(|_| Session::start(&config, FdDevice::new(fd, false), &server, &proxy))
        .map(|s| Box::into_raw(Box::new(s)) as jlong);
    let r = json(r);
    put(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_stats(mut env: JNIEnv, _c: JClass, handle: jlong) -> jstring {
    let s = if handle == 0 {
        "{}".to_string()
    } else {
        serde_json::to_string(&unsafe { &*(handle as *const Session) }.stats()).unwrap_or_default()
    };
    put(&mut env, s)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_stop(_env: JNIEnv, _c: JClass, handle: jlong) {
    if handle != 0 {
        drop(unsafe { Box::from_raw(handle as *mut Session) });
    }
    crate::socks::set_protect(None);
}

/// `{"ok":true,"value":{fields,problems,own_public_key}}` for a profile's text ("" for a new one).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_profileFields(mut env: JNIEnv, _c: JClass, config: JString) -> jstring {
    let config = get(&mut env, &config);
    let r = json(crate::editor::fields(&config));
    put(&mut env, r)
}

/// Applies a JSON object of field changes; `{"ok":true,"value":{text,problems}}`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_profileUpdate(mut env: JNIEnv, _c: JClass, config: JString, changes: JString) -> jstring {
    let (config, changes) = (get(&mut env, &config), get(&mut env, &changes));
    let r = json(crate::editor::update(&config, &changes));
    put(&mut env, r)
}

/// `{"private":..,"public":..}`, a new WireGuard key pair.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_securetunnel_app_TunnelCore_generateKeypair(mut env: JNIEnv, _c: JClass) -> jstring {
    let r = crate::editor::generate_keypair().to_string();
    put(&mut env, r)
}

//! "Connect at system startup" (the original's AutoConnectService: connect
//! before anyone signs in). The selected profile is saved to the boot folder
//! and the system starts the built-in engine with it at boot:
//! Windows: a scheduled task at startup running as SYSTEM;
//! Linux: a systemd service; macOS: a LaunchDaemon.
//! When someone signs in, the window picks the running tunnel back up.

use std::path::{Path, PathBuf};
#[cfg(any(windows, target_os = "macos"))]
use std::process::Command;

#[cfg_attr(not(windows), allow(dead_code))]
pub const TASK_NAME: &str = "SecureTunnel Connect";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const UNIT: &str = "secure-tunnel-boot.service";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const DAEMON: &str = "org.securetunnel.boot";

pub fn boot_dir() -> PathBuf {
    crate::store::base_dir().join("boot")
}

/// Is a tunnel file in the boot folder (which `down` must not delete)?
pub fn is_boot_conf(p: &Path) -> bool {
    p.parent().map(|d| d == boot_dir()).unwrap_or(false)
}

/// Turns startup connection on (with this tunnel file text) or off.
pub fn set(on: bool, iface: &str, conf_text: &str) -> Result<(), String> {
    let dir = boot_dir();
    let exe = crate::flatpak::host_path(&std::env::current_exe().map_err(|e| e.to_string())?);
    if on {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let conf = dir.join(format!("{iface}.conf"));
        std::fs::write(&conf, conf_text).map_err(|e| e.to_string())?;
        crate::store::restrict_permissions(&conf);
        install(&exe, &conf)
    } else {
        let r = uninstall();
        let _ = std::fs::remove_dir_all(&dir);
        r
    }
}

#[cfg(windows)]
fn elevated_powershell(script: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let encoded: String = {
        // -EncodedCommand takes UTF-16LE base64, which avoids quoting trouble.
        use base64::Engine as _;
        let bytes: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    };
    let outer = format!(
        "$p = Start-Process -FilePath powershell -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{encoded}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode"
    );
    let o = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &outer])
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err("Administrator approval is needed to change startup connection.".into()) }
}

#[cfg(windows)]
fn install(exe: &Path, conf: &Path) -> Result<(), String> {
    let q = |s: &str| s.replace('\'', "''");
    let script = format!(
        "$a = New-ScheduledTaskAction -Execute '{}' -Argument '--tunnel-helper \"{}\"'; \
         $t = New-ScheduledTaskTrigger -AtStartup; \
         $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; \
         $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero); \
         Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null",
        q(&exe.display().to_string()),
        q(&conf.display().to_string())
    );
    elevated_powershell(&script)
}

#[cfg(windows)]
fn uninstall() -> Result<(), String> {
    elevated_powershell(&format!("Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue"))
}

#[cfg(windows)]
pub fn installed() -> bool {
    use std::os::windows::process::CommandExt;
    Command::new("schtasks").args(["/Query", "/TN", TASK_NAME]).creation_flags(0x0800_0000).output().map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn root_sh(script: &str) -> Result<(), String> {
    let o = crate::flatpak::host_command("pkexec").args(["sh", "-c", script]).output().map_err(|e| format!("Could not ask for administrator rights: {e}"))?;
    if o.status.success() { Ok(()) } else { Err(format!("Administrator approval is needed: {}", String::from_utf8_lossy(&o.stderr).trim())) }
}

#[cfg(target_os = "linux")]
fn install(exe: &Path, conf: &Path) -> Result<(), String> {
    let unit = format!(
        "[Unit]\nDescription=Secure Tunnel connection at startup\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=\"{}\" --tunnel-helper \"{}\"\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n",
        exe.display(),
        conf.display()
    );
    let tmp = boot_dir().join(UNIT);
    std::fs::write(&tmp, unit).map_err(|e| e.to_string())?;
    root_sh(&format!("cp '{}' /etc/systemd/system/{UNIT} && systemctl daemon-reload && systemctl enable {UNIT}", tmp.display()))
}

#[cfg(target_os = "linux")]
fn uninstall() -> Result<(), String> {
    root_sh(&format!("systemctl disable {UNIT}; rm -f /etc/systemd/system/{UNIT}; systemctl daemon-reload"))
}

#[cfg(target_os = "linux")]
pub fn installed() -> bool {
    // Inside Flatpak the host's /etc is visible at /run/host/etc.
    let etc = if crate::flatpak::active() { "/run/host/etc" } else { "/etc" };
    Path::new(etc).join("systemd/system").join(UNIT).exists()
}

#[cfg(target_os = "macos")]
fn admin_sh(shell: &str) -> Result<(), String> {
    let script = format!("do shell script \"{}\" with administrator privileges", shell.replace('\\', "\\\\").replace('"', "\\\""));
    let o = Command::new("osascript").arg("-e").arg(script).output().map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err("Administrator approval is needed to change startup connection.".into()) }
}

#[cfg(target_os = "macos")]
fn install(exe: &Path, conf: &Path) -> Result<(), String> {
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{DAEMON}</string><key>ProgramArguments</key><array><string>{}</string><string>--tunnel-helper</string><string>{}</string></array><key>RunAtLoad</key><true/></dict></plist>\n",
        exe.display(),
        conf.display()
    );
    let tmp = boot_dir().join(format!("{DAEMON}.plist"));
    std::fs::write(&tmp, plist).map_err(|e| e.to_string())?;
    admin_sh(&format!(
        "cp '{}' /Library/LaunchDaemons/{DAEMON}.plist && chown root:wheel /Library/LaunchDaemons/{DAEMON}.plist && chmod 644 /Library/LaunchDaemons/{DAEMON}.plist",
        tmp.display()
    ))
}

#[cfg(target_os = "macos")]
fn uninstall() -> Result<(), String> {
    admin_sh(&format!("rm -f /Library/LaunchDaemons/{DAEMON}.plist"))
}

#[cfg(target_os = "macos")]
pub fn installed() -> bool {
    Path::new("/Library/LaunchDaemons").join(format!("{DAEMON}.plist")).exists()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn install(_e: &Path, _c: &Path) -> Result<(), String> {
    Err("Not supported on this system".into())
}
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn uninstall() -> Result<(), String> {
    Ok(())
}
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn installed() -> bool {
    false
}

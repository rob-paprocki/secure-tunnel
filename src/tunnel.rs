//! Connection control for the window. The tunnel itself runs in the built-in
//! engine (`engine.rs`) inside a helper process with administrator rights;
//! this worker starts and stops it and reads its status on a 200 ms loop,
//! refreshing statistics when more than a second has passed (the original's
//! service rules). Nothing outside the app has to be installed.

use std::collections::VecDeque;
use std::path::PathBuf;
#[allow(unused_imports)]
use std::process::Command;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::engine::{self, Status};
use crate::profile::Profile;
use crate::stats;
use crate::store::{self, LogLevel};

pub const MAX_LOG_LINES: usize = 5000;
/// How long to wait for the administrator prompt and the helper to report.
pub const HELPER_START_LIMIT: Duration = Duration::from_secs(120);
/// A status older than this means the helper is gone.
pub const STATUS_STALE_SECS: u64 = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub time: SystemTime,
    pub level: LogLevel,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct EngineInfo {
    pub name: String,
}

impl Default for EngineInfo {
    fn default() -> Self {
        let mut name = format!("Built in: {}", engine::ENGINE_NAME);
        if cfg!(windows) {
            name.push_str(&format!(" with Wintun {}", engine::WINTUN_VERSION));
        }
        EngineInfo { name }
    }
}

#[derive(Clone, Debug)]
pub struct Shared {
    pub state: State,
    pub profile: String,
    pub endpoint: String,
    pub since: Option<Instant>,
    pub rx: u64,
    pub tx: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub handshake: bool,
    /// Round trip of the last handshake, from the engine.
    pub rtt: Option<u32>,
    /// Weighted loss over the engine's recent sessions.
    pub loss: Option<f32>,
    pub conn_id: u64,
    pub error: String,
    pub engine: EngineInfo,
    pub logs: VecDeque<LogLine>,
}

impl Default for Shared {
    fn default() -> Self {
        Shared {
            state: State::Disconnected,
            profile: String::new(),
            endpoint: String::new(),
            since: None,
            rx: 0,
            tx: 0,
            rx_rate: 0,
            tx_rate: 0,
            handshake: false,
            rtt: None,
            loss: None,
            conn_id: 0,
            error: String::new(),
            engine: EngineInfo::default(),
            logs: VecDeque::new(),
        }
    }
}

impl Shared {
    pub fn log(&mut self, level: LogLevel, text: impl Into<String>) {
        let text = text.into();
        write_log_file(level, &text);
        self.logs.push_back(LogLine { time: SystemTime::now(), level, text });
        while self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }
}

/// Folder of the log files (the Logs page opens it).
pub fn log_dir() -> PathBuf {
    store::base_dir().join("logs")
}

/// Largest log file before it is moved to `secure-tunnel.1.log`.
pub const LOG_FILE_MAX: u64 = 5 * 1024 * 1024;

fn write_log_file(level: LogLevel, text: &str) {
    use std::io::Write;
    static LIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // Screenshot runs never write files.
    if !*LIVE.get_or_init(|| !std::env::args().any(|a| a.starts_with("--screenshot"))) {
        return;
    }
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("secure-tunnel.log");
    if std::fs::metadata(&path).map(|m| m.len() > LOG_FILE_MAX).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("secure-tunnel.1.log"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let secs = SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "{secs} {level:?} {text}");
    }
}

#[derive(Clone)]
pub struct ConnectRequest {
    pub name: String,
    pub profile: Profile,
    pub timeout_secs: u32,
    pub reconnect: bool,
    pub use_junk: bool,
    pub junk: (String, String, String),
    /// Global split tunnelling replacing the profile's.
    pub split_override: Option<SplitOverride>,
    pub bypass_lan: bool,
    pub kill_switch: bool,
    pub preserve_lock: bool,
    pub tcp_termination: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SplitOverride {
    pub allowed_ips: String,
    pub disallowed_ips: String,
    pub allowed_apps: String,
    pub disallowed_apps: String,
}

pub enum Cmd {
    Connect(Box<ConnectRequest>),
    Disconnect,
}

pub struct Tunnel {
    pub shared: Arc<Mutex<Shared>>,
    tx: Option<Sender<Cmd>>,
}

impl Tunnel {
    /// `live = false` (screenshot runs) never starts the worker.
    pub fn new(live: bool) -> Self {
        let shared = Arc::new(Mutex::new(Shared::default()));
        if !live {
            return Tunnel { shared, tx: None };
        }
        let (tx, rx) = channel();
        let s2 = shared.clone();
        std::thread::spawn(move || worker(s2, rx));
        Tunnel { shared, tx: Some(tx) }
    }
    pub fn send(&self, c: Cmd) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(c);
        }
    }
    pub fn sender(&self) -> Option<Sender<Cmd>> {
        self.tx.clone()
    }
    /// Everything but the log, cheap enough to take every frame.
    pub fn snapshot(&self) -> Shared {
        self.shared
            .lock()
            .map(|s| clone_head(&s))
            .unwrap_or_default()
    }

    /// The log lines, for the Logs and Report pages.
    pub fn logs(&self) -> Shared {
        self.shared.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

pub fn run_dir() -> PathBuf {
    store::base_dir().join("run")
}

struct Active {
    conf: PathBuf,
    req: Box<ConnectRequest>,
    /// When the connect attempt began (the timeout counts from here).
    started: Instant,
    launched: Instant,
    last_poll: Instant,
    prev: (u64, u64),
    log_seen: usize,
    rx_moved: Instant,
    tx_moved: Instant,
}

/// A connect attempt waiting to be retried (service retry back-off).
struct Retry {
    req: Box<ConnectRequest>,
    at: Instant,
    delay_ms: u64,
    started: Instant,
    last_error: String,
}

fn clone_head(s: &Shared) -> Shared {
    Shared {
        state: s.state,
        profile: s.profile.clone(),
        endpoint: s.endpoint.clone(),
        since: s.since,
        rx: s.rx,
        tx: s.tx,
        rx_rate: s.rx_rate,
        tx_rate: s.tx_rate,
        handshake: s.handshake,
        rtt: s.rtt,
        loss: s.loss,
        conn_id: s.conn_id,
        error: s.error.clone(),
        engine: s.engine.clone(),
        logs: VecDeque::new(),
    }
}

fn reset_stats(s: &mut Shared) {
    s.since = None;
    s.rx_rate = 0;
    s.tx_rate = 0;
    s.rtt = None;
    s.loss = None;
}

fn set(shared: &Arc<Mutex<Shared>>, f: impl FnOnce(&mut Shared)) {
    if let Ok(mut s) = shared.lock() {
        f(&mut s);
    }
}

fn worker(shared: Arc<Mutex<Shared>>, rx: Receiver<Cmd>) {
    let mut active: Option<Active> = reattach(&shared);
    let mut retry: Option<Retry> = None;
    loop {
        match rx.recv_timeout(stats::LOOP_TICK) {
            Ok(Cmd::Connect(req)) => {
                retry = None;
                if let Some(a) = active.take() {
                    down(&shared, &a);
                }
                let started = Instant::now();
                match up(&shared, req, started) {
                    Ok(a) => active = Some(a),
                    Err(f) => retry = fail(&shared, f, started, None),
                }
            }
            Ok(Cmd::Disconnect) => {
                retry = None;
                if let Some(a) = active.take() {
                    set(&shared, |s| s.state = State::Disconnecting);
                    down(&shared, &a);
                }
                set(&shared, |s| {
                    if s.state != State::Disconnected {
                        let p = s.profile.clone();
                        s.log(LogLevel::ConnectionStatus, format!("Disconnected from {p}"));
                    }
                    s.state = State::Disconnected;
                    s.conn_id += 1;
                    reset_stats(s);
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return,
        }

        // Retry a failed connect with back-off until the timeout runs out.
        if retry.as_ref().map(|r| Instant::now() >= r.at).unwrap_or(false) {
            if let Some(r) = retry.take() {
                let (delay, last, started) = (r.delay_ms, r.last_error.clone(), r.started);
                match up(&shared, r.req, started) {
                    Ok(a) => active = Some(a),
                    Err(f) => retry = fail(&shared, f, started, Some((delay, last))),
                }
            }
        }

        let mut drop_it: Option<UpFailure> = None;
        let mut reconnect = false;
        if let Some(a) = active.as_mut() {
            let secs = a.last_poll.elapsed().as_secs_f64();
            if secs > stats::STATS_MIN_INTERVAL_SECS {
                a.last_poll = Instant::now();
                match engine::read_status(&a.conf) {
                    None => {
                        if a.launched.elapsed() > HELPER_START_LIMIT {
                            drop_it = Some(failure(a, "The tunnel didn't start. Administrator approval may have been declined.".into(), false));
                        }
                    }
                    Some(st) => {
                        // Copy new helper log lines.
                        if st.log.len() < a.log_seen {
                            a.log_seen = 0;
                        }
                        let fresh: Vec<String> = st.log.iter().skip(a.log_seen).cloned().collect();
                        a.log_seen = st.log.len();
                        set(&shared, |s| fresh.into_iter().for_each(|l| s.log(LogLevel::Info, l)));
                        let stale = engine::now_secs().saturating_sub(st.updated) > STATUS_STALE_SECS;
                        match st.state.as_str() {
                            "error" => {
                                let retryable = is_retryable(&st.error);
                                drop_it = Some(failure(a, st.error.clone(), retryable));
                            }
                            "stopped" => {
                                set(&shared, |s| s.log(LogLevel::Warning, "The tunnel stopped."));
                                reconnect = a.req.reconnect && handshake_done(&shared);
                                drop_it = Some(failure(a, String::new(), false));
                            }
                            _ if stale && a.launched.elapsed() > Duration::from_secs(STATUS_STALE_SECS) => {
                                set(&shared, |s| s.log(LogLevel::Warning, "The tunnel helper stopped answering."));
                                reconnect = a.req.reconnect && handshake_done(&shared);
                                drop_it = Some(failure(a, String::new(), false));
                            }
                            "up" => poll_up(&shared, a, &st, secs, &mut drop_it, &mut reconnect),
                            _ => {}
                        }
                    }
                }
            }
        }
        if let Some(f) = drop_it {
            let started = active.as_ref().map(|a| a.started).unwrap_or_else(Instant::now);
            if let Some(a) = active.take() {
                down(&shared, &a);
            }
            set(&shared, |s| {
                s.state = State::Disconnected;
                s.conn_id += 1;
                reset_stats(s);
            });
            if reconnect {
                set(&shared, |s| s.log(LogLevel::Info, "Reconnecting..."));
                let started = Instant::now();
                match up(&shared, f.req, started) {
                    Ok(a) => active = Some(a),
                    Err(f) => retry = fail(&shared, f, started, None),
                }
            } else if !f.message.is_empty() {
                retry = fail(&shared, f, started, None);
            }
        }
    }
}

fn poll_up(shared: &Arc<Mutex<Shared>>, a: &mut Active, st: &Status, secs: f64, drop_it: &mut Option<UpFailure>, reconnect: &mut bool) {
    let connected = handshake_done(shared);
    let newly = !connected && st.handshake_secs.is_some();
    let prev = a.prev;
    if st.rx != prev.0 {
        a.rx_moved = Instant::now();
    }
    if st.tx != prev.1 {
        a.tx_moved = Instant::now();
    }
    set(shared, |s| {
        if newly {
            // The server's handshake response arrived: connected.
            s.handshake = true;
            s.state = State::Connected;
            s.since = Some(Instant::now());
            let p = s.profile.clone();
            s.log(LogLevel::ConnectionStatus, format!("Connected to {p}"));
        } else if connected {
            s.rx_rate = stats::rate_bits(prev.0, st.rx, secs).unwrap_or(s.rx_rate);
            s.tx_rate = stats::rate_bits(prev.1, st.tx, secs).unwrap_or(s.tx_rate);
        }
        s.rx = st.rx;
        s.tx = st.tx;
        s.rtt = st.rtt_ms;
        s.loss = if connected || newly { Some(st.loss) } else { None };
    });
    a.prev = (st.rx, st.tx);
    let timeout = a.req.timeout_secs;
    if !connected && !newly && timeout > 0 && a.started.elapsed().as_secs_f64() > timeout as f64 {
        let name = a.req.name.clone();
        *drop_it = Some(failure(a, format!("Connection timed out while connecting to {name}"), false));
        return;
    }
    // Sending but hearing nothing back for longer than the liveness window,
    // with the last handshake older than REJECT_AFTER_TIME: the server is gone.
    if connected
        && a.rx_moved.elapsed().as_secs() > stats::LIVENESS_IDLE_SECS
        && a.tx_moved.elapsed().as_secs() < stats::LIVENESS_IDLE_SECS
        && st.handshake_secs.unwrap_or(0) > stats::REJECT_AFTER_SECS
    {
        set(shared, |s| s.log(LogLevel::Warning, "The server stopped answering."));
        *reconnect = a.req.reconnect;
        *drop_it = Some(failure(a, String::new(), false));
    }
}

fn handshake_done(shared: &Arc<Mutex<Shared>>) -> bool {
    shared.lock().map(|s| s.handshake).unwrap_or(false)
}

/// Picks up a tunnel still running from an earlier session of the app.
fn reattach(shared: &Arc<Mutex<Shared>>) -> Option<Active> {
    // A tunnel started from the window, or at system startup.
    let entries: Vec<PathBuf> = [run_dir(), crate::boot::boot_dir()]
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flat_map(|rd| rd.flatten().map(|e| e.path()).collect::<Vec<_>>())
        .collect();
    for p in entries {
        if p.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        let Some(st) = engine::read_status(&p) else { continue };
        let fresh = engine::now_secs().saturating_sub(st.updated) <= STATUS_STALE_SECS;
        if !fresh || st.state != "up" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Ok(profile) = Profile::parse(&text) else { continue };
        let flags = engine::Flags::parse(&text);
        let now = Instant::now();
        set(shared, |s| {
            s.profile = st.profile.clone();
            s.endpoint = profile.endpoint.clone();
            s.state = if st.handshake_secs.is_some() { State::Connected } else { State::Connecting };
            s.handshake = st.handshake_secs.is_some();
            s.since = st.handshake_secs.map(|_| now);
            s.log(LogLevel::ConnectionStatus, format!("Still connected to {}", st.profile));
        });
        return Some(Active {
            conf: p,
            req: Box::new(ConnectRequest {
                name: st.profile.clone(),
                profile,
                timeout_secs: 0,
                reconnect: true,
                use_junk: false,
                junk: Default::default(),
                split_override: None,
                bypass_lan: false,
                kill_switch: flags.kill_switch,
                preserve_lock: flags.preserve_lock,
                tcp_termination: flags.tcp_termination,
            }),
            started: now,
            launched: now,
            last_poll: now,
            prev: (st.rx, st.tx),
            log_seen: st.log.len(),
            rx_moved: now,
            tx_moved: now,
        });
    }
    None
}

struct UpFailure {
    req: Box<ConnectRequest>,
    message: String,
    retryable: bool,
}

fn failure(a: &Active, message: String, retryable: bool) -> UpFailure {
    UpFailure { req: clone_req(&a.req), message, retryable }
}

/// Decides between retrying (network-type errors, inside the timeout) and
/// giving up. Back-off: 200 ms after a new error, doubling to 5 s on repeats.
fn fail(shared: &Arc<Mutex<Shared>>, f: UpFailure, started: Instant, prev: Option<(u64, String)>) -> Option<Retry> {
    let timeout = f.req.timeout_secs;
    let in_time = timeout == 0 || started.elapsed().as_secs_f64() <= timeout as f64;
    if f.retryable && in_time {
        let delay = match &prev {
            Some((d, last)) if *last == f.message => (*d * 2).min(stats::RETRY_MAX_MS),
            _ => stats::RETRY_START_MS,
        };
        let new_error = prev.as_ref().map(|(_, l)| l != &f.message).unwrap_or(true);
        set(shared, |s| {
            if new_error {
                s.log(LogLevel::Warning, format!("{} (retrying)", f.message));
            }
            s.state = State::Connecting;
        });
        return Some(Retry { req: f.req, at: Instant::now() + Duration::from_millis(delay), delay_ms: delay, started, last_error: f.message });
    }
    let msg = if f.retryable { format!("Connection timed out while connecting to {}", f.req.name) } else { f.message };
    set(shared, |s| {
        s.error = msg.clone();
        s.log(LogLevel::Error, msg);
        s.state = State::Disconnected;
        reset_stats(s);
    });
    None
}

/// Errors worth retrying: name resolution and network trouble.
fn is_retryable(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    ["resolve", "name or service", "temporary failure", "network is unreachable", "no route", "host is down", "could not reach"]
        .iter()
        .any(|k| m.contains(k))
}

fn clone_req(r: &ConnectRequest) -> Box<ConnectRequest> {
    Box::new(ConnectRequest {
        name: r.name.clone(),
        profile: r.profile.clone(),
        timeout_secs: r.timeout_secs,
        reconnect: r.reconnect,
        use_junk: r.use_junk,
        junk: r.junk.clone(),
        split_override: r.split_override.clone(),
        bypass_lan: r.bypass_lan,
        kill_switch: r.kill_switch,
        preserve_lock: r.preserve_lock,
        tcp_termination: r.tcp_termination,
    })
}

/// The profile with the global settings layered on (original "global settings").
pub fn merged_profile(req: &ConnectRequest) -> Profile {
    let mut p = req.profile.clone();
    if let Some(o) = &req.split_override {
        if !o.allowed_ips.trim().is_empty() {
            p.allowed_ips = o.allowed_ips.clone();
        }
        p.disallowed_ips = o.disallowed_ips.clone();
        p.allowed_apps = o.allowed_apps.clone();
        p.disallowed_apps = o.disallowed_apps.clone();
    }
    if req.bypass_lan {
        p.bypass_lan = "true".into();
    }
    if req.use_junk && p.jc.is_empty() {
        p.jc = req.junk.0.clone();
        p.jmin = req.junk.1.clone();
        p.jmax = req.junk.2.clone();
    }
    p
}

/// The tunnel file the engine reads: profile name, switches, then the profile.
pub fn tunnel_file_text(req: &ConnectRequest) -> String {
    let flags = engine::Flags { kill_switch: req.kill_switch, preserve_lock: req.preserve_lock, tcp_termination: req.tcp_termination };
    format!("# profile: {}\n{}{}", req.name, flags.header(), merged_profile(req).to_conf())
}

fn up(shared: &Arc<Mutex<Shared>>, req: Box<ConnectRequest>, started: Instant) -> Result<Active, UpFailure> {
    let p = merged_profile(&req);
    let endpoint = p.endpoint.clone();
    let first = started.elapsed() < Duration::from_millis(50);
    set(shared, |s| {
        s.state = State::Connecting;
        s.profile = req.name.clone();
        s.endpoint = endpoint.clone();
        s.error.clear();
        s.handshake = false;
        s.rx = 0;
        s.tx = 0;
        reset_stats(s);
        if first {
            s.conn_id += 1;
            s.log(LogLevel::ConnectionStatus, format!("Connecting to {}", req.name));
            for f in p.unenforced_features() {
                s.log(LogLevel::Warning, format!("Not enforced in this version: {f}"));
            }
        }
    });
    let dir = run_dir();
    let _ = std::fs::create_dir_all(&dir);
    let conf = dir.join(format!("{}.conf", interface_name(&req.name)));
    // A helper still running for this name is stopped first.
    if let Some(st) = engine::read_status(&conf) {
        if st.state == "up" || st.state == "starting" {
            stop_helper(&conf);
        }
    }
    for f in [engine::status_path(&conf), engine::stop_path(&conf)] {
        let _ = std::fs::remove_file(f);
    }
    let flags = engine::Flags { kill_switch: req.kill_switch, preserve_lock: req.preserve_lock, tcp_termination: req.tcp_termination };
    let body = format!("# profile: {}\n{}{}", req.name, flags.header(), p.to_conf());
    if let Err(e) = std::fs::write(&conf, body) {
        return Err(UpFailure { req, message: format!("Failed to write tunnel file: {e}"), retryable: false });
    }
    store::restrict_permissions(&conf);
    #[cfg(target_os = "macos")]
    if let Some(m) = crate::apps::mode(&p.allowed_apps, &p.disallowed_apps) {
        // Per-app routing on macOS runs in the app's Network Extension.
        let (mode, list) = match m {
            crate::apps::Mode::OnlyThese(a) => ("only", a),
            crate::apps::Mode::Except(a) => ("except", a),
        };
        let sh = shared.clone();
        std::thread::spawn(move || {
            let log = |l: LogLevel, m: String| set(&sh, |s| s.log(l, m));
            match crate::apps::mac_netext(&["install".to_string()]) {
                Ok(t) => log(LogLevel::Info, format!("Per-app routing extension: {t}")),
                Err(e) => log(LogLevel::Warning, format!("Per-app routing extension: {e}")),
            }
            match crate::apps::mac_netext(&["enable".to_string(), mode.to_string(), list.join("
")]) {
                Ok(t) => log(LogLevel::Info, format!("Per-app routing: {t}")),
                Err(e) => log(LogLevel::Error, format!("Per-app routing could not start: {e}")),
            }
        });
    }
    set(shared, |s| s.log(LogLevel::Info, "Starting the built-in tunnel engine (administrator approval needed)"));
    match engine::launch_helper(&conf) {
        Ok(()) => {
            let now = Instant::now();
            Ok(Active { conf, req, started, launched: now, last_poll: now, prev: (0, 0), log_seen: 0, rx_moved: now, tx_moved: now })
        }
        Err(e) => Err(UpFailure { req, message: e, retryable: false }),
    }
}

/// Asks the helper to stop and waits up to the disconnect limit.
fn stop_helper(conf: &std::path::Path) -> bool {
    let _ = std::fs::write(engine::stop_path(conf), b"stop");
    let until = Instant::now() + stats::DISCONNECT_TIMEOUT;
    while Instant::now() < until {
        match engine::read_status(conf) {
            Some(st) if st.state == "up" || st.state == "starting" => {
                if engine::now_secs().saturating_sub(st.updated) > STATUS_STALE_SECS {
                    return false;
                }
            }
            _ => return true,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn down(shared: &Arc<Mutex<Shared>>, a: &Active) {
    let ok = stop_helper(&a.conf);
    #[cfg(target_os = "macos")]
    if crate::apps::mac_controller().is_some() {
        let _ = crate::apps::mac_netext(&["disable".to_string()]);
    }
    for f in [engine::status_path(&a.conf), engine::stop_path(&a.conf)] {
        let _ = std::fs::remove_file(f);
    }
    if !crate::boot::is_boot_conf(&a.conf) {
        let _ = std::fs::remove_file(&a.conf);
    }
    set(shared, |s| {
        if ok {
            s.log(LogLevel::Info, "Tunnel stopped");
        } else {
            s.log(LogLevel::Warning, "The tunnel didn't confirm it stopped within 30 s");
        }
    });
}

#[allow(dead_code)]
fn output_text(o: &std::process::Output) -> String {
    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
    s.push_str(&String::from_utf8_lossy(&o.stderr));
    s
}

#[cfg(target_os = "windows")]
fn hidden(c: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    c.creation_flags(0x0800_0000) // CREATE_NO_WINDOW
}

pub fn interface_name(profile: &str) -> String {
    let mut s: String = profile
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || "_=+.-".contains(c) {
                Some(c)
            } else if c == ' ' {
                Some('-')
            } else {
                None
            }
        })
        .take(15)
        .collect();
    if s.is_empty() || s.starts_with('.') {
        s = "tunnel0".into();
    }
    s
}

// ---------- start on sign-in ----------

pub fn set_autostart(on: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    {
        let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let mut c = Command::new("reg");
        if on {
            c.args(["add", key, "/v", "SecureTunnel", "/t", "REG_SZ", "/d", &format!("\"{}\"", exe.display()), "/f"]);
        } else {
            c.args(["delete", key, "/v", "SecureTunnel", "/f"]);
        }
        let o = hidden(&mut c).output().map_err(|e| e.to_string())?;
        if !o.status.success() && on {
            return Err(output_text(&o));
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Inside Flatpak, XDG_CONFIG_HOME is the sandbox's own folder; the session
        // reads ~/.config/autostart (granted with --filesystem=xdg-config/autostart:create).
        let base = directories::BaseDirs::new().ok_or("no home")?;
        let dir = if crate::flatpak::active() { base.home_dir().join(".config/autostart") } else { base.config_dir().join("autostart") };
        let f = dir.join("secure-tunnel.desktop");
        let exec = if crate::flatpak::active() { format!("flatpak run {}", crate::flatpak::APP_ID) } else { format!("\"{}\"", exe.display()) };
        if on {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(&f, format!("[Desktop Entry]\nType=Application\nName=Secure Tunnel\nExec={exec}\nX-GNOME-Autostart-enabled=true\n"))
                .map_err(|e| e.to_string())?;
        } else {
            let _ = std::fs::remove_file(f);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let dir = directories::BaseDirs::new().ok_or("no home")?.home_dir().join("Library/LaunchAgents");
        let f = dir.join("org.securetunnel.app.plist");
        if on {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            std::fs::write(&f, format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>org.securetunnel.app</string><key>ProgramArguments</key><array><string>{}</string></array><key>RunAtLoad</key><true/></dict></plist>\n", exe.display()))
                .map_err(|e| e.to_string())?;
        } else {
            let _ = std::fs::remove_file(f);
        }
    }
    let _ = exe;
    Ok(())
}

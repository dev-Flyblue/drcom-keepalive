use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Local, NaiveTime};

const HOST: &str = "10.254.1.38";
const SECRET: &str = "drcom";

const USER_IP: &str = "10.206.127.249";
const USER_MAC: &str = "00783226604e";
const USER_IPV6: &str = "";
const VLAN: &str = "1";

/// 心跳间隔
const HEARTBEAT_SECS: u64 = 5;
/// 外部探测间隔
const PROBE_SECS: u64 = 20;
/// 检测到离线后的确认次数
const CONFIRM_ROUNDS: u32 = 3;
/// 每次登录最多重试
const LOGIN_RETRIES: u32 = 3;

// ======================== XOR ========================

fn xor_key(s: &str) -> u8 { s.bytes().fold(0u8, |a, b| a ^ b) }
fn xor_enc(plain: &str, key: u8) -> String {
    plain.bytes().map(|b| format!("{:02x}", b ^ key)).collect()
}
fn ue(s: &str) -> String {
    s.replace('%', "%25").replace(' ', "%20")
     .replace('+', "%2B").replace('&', "%26").replace('=', "%3D")
}

// ======================== 时间段 ========================

#[derive(Clone)]
struct TimeRange { start: NaiveTime, end: NaiveTime }
impl TimeRange {
    fn parse(s: &str) -> Option<Self> {
        let p: Vec<&str> = s.trim().split('-').collect();
        if p.len() != 2 { return None; }
        Some(Self {
            start: NaiveTime::parse_from_str(p[0].trim(), "%H:%M").ok()?,
            end: NaiveTime::parse_from_str(p[1].trim(), "%H:%M").ok()?,
        })
    }
    fn contains(&self, t: NaiveTime) -> bool {
        if self.start <= self.end { t >= self.start && t < self.end }
        else { t >= self.start || t < self.end }
    }
}
fn is_active(r: &[TimeRange]) -> bool {
    if r.is_empty() { return true; }
    let now = Local::now().time();
    r.iter().any(|r| r.contains(now))
}

// ======================== JSONP ========================

fn parse_jsonp(t: &str) -> Option<serde_json::Value> {
    let s = t.find('(')?;
    let e = t.rfind(')')?;
    if s >= e { return None; }
    serde_json::from_str(&t[s + 1..e]).ok()
}

// ======================== 日志 ========================

fn ts() -> String { Local::now().format("%H:%M:%S").to_string() }
macro_rules! info { ($($a:tt)*) => { println!("[{}]      {}", ts(), format!($($a)*)) } }
macro_rules! ok   { ($($a:tt)*) => { println!("[{}]  OK  {}", ts(), format!($($a)*)) } }
macro_rules! warn { ($($a:tt)*) => { println!("[{}]  !!  {}", ts(), format!($($a)*)) } }
macro_rules! err  { ($($a:tt)*) => { eprintln!("[{}] ERR  {}", ts(), format!($($a)*)) } }

// ======================== 核心 ========================

struct App {
    fast_cli: reqwest::blocking::Client,   // 心跳用，短超时
    login_cli: reqwest::blocking::Client,  // 登录用，长超时
    probe_cli: reqwest::blocking::Client,  // 外部探测
    key: u8,
    seq: u32,
    account: String,
    password: String,
}

impl App {
    fn new(account: String, password: String) -> Self {
        Self {
            fast_cli: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .no_proxy().build().unwrap(),
            login_cli: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .no_proxy().build().unwrap(),
            probe_cli: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build().unwrap(),
            key: xor_key(SECRET),
            seq: 1000,
            account, password,
        }
    }

    fn rv() -> u16 {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().subsec_millis() as u16;
        500 + (ms % 9500)
    }

    fn cb(&mut self) -> String { self.seq += 1; format!("dr{}", self.seq) }

    fn enc_qs(&mut self, params: &[(&str, &str)]) -> String {
        let cb = self.cb();
        let mut parts = vec![format!("callback={}", ue(&xor_enc(&cb, self.key)))];
        for &(k, v) in params {
            parts.push(format!("{}={}", ue(k), ue(&xor_enc(v, self.key))));
        }
        parts.push(format!("jsVersion={}", ue(&xor_enc("4.X", self.key))));
        parts.push("encrypt=1".into());
        parts.push(format!("v={}", Self::rv()));
        parts.push("lang=zh".into());
        parts.join("&")
    }

    // -------- chkstatus 单次心跳 --------
    fn chkstatus(&mut self) -> Option<bool> {
        let cb = self.cb();
        let url = format!(
            "http://{}:80/drcom/chkstatus?callback={}&jsVersion=4.X&v={}&lang=zh",
            HOST, cb, Self::rv()
        );
        let resp = self.fast_cli.get(&url).send().ok()?;
        let text = resp.text().ok()?;
        let j = parse_jsonp(&text)?;
        Some(j["result"].as_i64().unwrap_or(-1) == 1)
    }

    // -------- 多次确认是否真的离线 --------
    fn confirm_offline(&mut self) -> bool {
        for _ in 0..CONFIRM_ROUNDS {
            std::thread::sleep(Duration::from_millis(500));
            if let Some(true) = self.chkstatus() {
                return false; // 其实在线，之前是误判
            }
        }
        true // 连续多次确认离线
    }

    // -------- 心跳 + 返回 (在线?, uid) --------
    fn heartbeat(&mut self) -> (bool, String) {
        let cb = self.cb();
        let url = format!(
            "http://{}:80/drcom/chkstatus?callback={}&jsVersion=4.X&v={}&lang=zh",
            HOST, cb, Self::rv()
        );
        match self.fast_cli.get(&url).send() {
            Ok(r) => match r.text() {
                Ok(t) => match parse_jsonp(&t) {
                    Some(j) => {
                        let on = j["result"].as_i64().unwrap_or(-1) == 1;
                        let uid = j["uid"].as_str().unwrap_or("").to_string();
                        (on, uid)
                    }
                    None => (false, "jsonp_err".into()),
                },
                Err(e) => (false, e.to_string()),
            },
            Err(e) => (false, e.to_string()),
        }
    }

    // -------- 外部连通性探测 --------
    fn probe_external(&self) -> bool {
        for url in &[
            "http://connect.rom.miui.com/generate_204",
            "http://www.msftconnecttest.com/connecttest.txt",
        ] {
            if let Ok(r) = self.probe_cli.get(*url).send() {
                let s = r.status().as_u16();
                if s == 200 || s == 204 { return true; }
            }
        }
        false
    }

    // -------- Portal 登录（带重试）--------
    fn login_with_retry(&mut self) -> bool {
        for attempt in 1..=LOGIN_RETRIES {
            let qs = self.enc_qs(&[
                ("login_method", "1"),
                ("user_account", &self.account.clone()),
                ("user_password", &self.password.clone()),
                ("wlan_user_ip", USER_IP),
                ("wlan_user_ipv6", USER_IPV6),
                ("wlan_vlan_id", VLAN),
                ("wlan_user_mac", USER_MAC),
                ("wlan_ac_ip", ""),
                ("wlan_ac_name", ""),
            ]);
            let url = format!("http://{}:803/eportal/portal/login?{}", HOST, qs);

            match self.login_cli.get(&url).send() {
                Ok(r) => {
                    if let Ok(text) = r.text() {
                        if let Some(j) = parse_jsonp(&text) {
                            let result = j["result"].as_i64().unwrap_or(-1);
                            if result == 1 {
                                // 登录成功，等待生效后确认
                                std::thread::sleep(Duration::from_secs(1));
                                if let Some(true) = self.chkstatus() {
                                    ok!("登录成功 (第{}次)", attempt);
                                    return true;
                                }
                                // chkstatus 还没生效，再等一下
                                std::thread::sleep(Duration::from_secs(2));
                                if let Some(true) = self.chkstatus() {
                                    ok!("登录成功 (延迟生效, 第{}次)", attempt);
                                    return true;
                                }
                                warn!("Portal 返回成功但 chkstatus 未确认 (第{}次)", attempt);
                                continue;
                            }
                            let msg = j["msg"].as_str().unwrap_or("?");
                            if attempt == LOGIN_RETRIES {
                                err!("登录失败: {}", msg);
                            }
                        }
                    }
                }
                Err(e) => {
                    if attempt == LOGIN_RETRIES {
                        err!("登录请求异常: {}", e);
                    }
                }
            }

            if attempt < LOGIN_RETRIES {
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        false
    }

    // -------- 确保在线（检测 + 自动重登）--------
    fn ensure_online(&mut self) -> bool {
        let (online, _) = self.heartbeat();
        if online { return true; }

        // 二次确认
        if !self.confirm_offline() {
            return true; // 误判，实际在线
        }

        info!("确认离线，自动登录...");
        self.login_with_retry()
    }
}

// ======================== main ========================

fn main() {
    println!("=============================================");
    println!("  校园网保活  |  掉线自动重登 + 时段控制");
    println!("=============================================\n");

    // 凭证
    let account = prompt("账号: ");
    let password = prompt_password("密码: ");

    // 时段
    println!();
    println!("  选择保活时段:");
    println!("  [1] 24小时全天");
    println!("  [2] 白天 (07:00 - 23:00)");
    println!("  [3] 工作时间 (08:00 - 18:00)");
    println!("  [4] 通宵 (22:00 - 08:00)");
    println!("  [5] 自定义");
    println!();
    let choice = prompt("选择 [1-5]: ");

    let ranges: Vec<TimeRange> = match choice.trim() {
        "2" => vec![TimeRange::parse("07:00-23:00").unwrap()],
        "3" => vec![TimeRange::parse("08:00-18:00").unwrap()],
        "4" => vec![TimeRange::parse("22:00-08:00").unwrap()],
        "5" => {
            println!();
            println!("  格式: HH:MM-HH:MM  多时段空格分隔  支持跨午夜");
            println!("  例: 08:00-12:00 14:00-22:00");
            println!();
            let input = prompt("时段: ");
            let parsed: Vec<TimeRange> = input.split_whitespace()
                .filter_map(|s| TimeRange::parse(s)).collect();
            if parsed.is_empty() { warn!("无效输入，使用 24h"); }
            parsed
        }
        _ => vec![],
    };

    if account.is_empty() || password.is_empty() {
        err!("账号密码不能为空");
        return;
    }

    println!();
    info!("心跳: {}s  确认轮次: {}  登录重试: {}", HEARTBEAT_SECS, CONFIRM_ROUNDS, LOGIN_RETRIES);
    if ranges.is_empty() {
        info!("时段: 24h 全天");
    } else {
        for r in &ranges {
            info!("时段: {} — {}", r.start.format("%H:%M"), r.end.format("%H:%M"));
        }
    }
    info!("账号: {}  密码: {}", account, "*".repeat(password.len()));

    let running = Arc::new(AtomicBool::new(true));
    { let r = running.clone(); ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); }).ok(); }

    let mut app = App::new(account, password);

    // 首次登录
    println!();
    info!("首次登录...");
    if app.ensure_online() {
        ok!("已上线");
    } else {
        err!("首次登录失败，请检查账号密码");
        err!("将持续重试...");
    }

    println!("\n--- 保活运行中 (Ctrl+C 退出) ---\n");

    let mut tick: u64 = 0;
    let mut paused = false;
    let mut fail_streak: u32 = 0;
    let mut last_probe = Instant::now();

    while running.load(Ordering::SeqCst) {
        tick += 1;

        // ---- 时段检查 ----
        if !is_active(&ranges) {
            if !paused {
                paused = true;
                info!("不在活跃时段，暂停");
            }
            sleep(&running, 30);
            continue;
        }
        if paused {
            paused = false;
            info!("进入活跃时段，恢复");
            app.ensure_online();
        }

        // ---- 心跳 ----
        let (online, uid) = app.heartbeat();

        if online {
            if fail_streak > 0 {
                ok!("恢复在线: {}", uid);
            } else if tick % 60 == 1 {
                // ~5分钟打印一次
                ok!("在线: {} (tick={})", uid, tick);
            }
            fail_streak = 0;
        } else {
            // 检测到可能离线 → 二次确认
            if app.confirm_offline() {
                fail_streak += 1;

                if fail_streak == 1 {
                    warn!("确认离线，自动登录...");
                }

                if fail_streak <= 5 || fail_streak % 15 == 0 {
                    if app.login_with_retry() {
                        fail_streak = 0;
                        continue;
                    }
                }

                if fail_streak == 6 {
                    err!("连续 {} 次重登失败，降低重试频率", fail_streak);
                }
            } else {
                // 误判，实际在线
                if fail_streak > 0 {
                    ok!("误判恢复，实际在线");
                    fail_streak = 0;
                }
            }
        }

        // ---- 外部探测（交叉验证）----
        if last_probe.elapsed() >= Duration::from_secs(PROBE_SECS) && fail_streak == 0 {
            let ext_ok = app.probe_external();
            if !ext_ok && online {
                // chkstatus 说在线但外部不通 → Portal 可能假在线
                warn!("chkstatus 在线但外部不通，预防性重登...");
                app.login_with_retry();
            }
            last_probe = Instant::now();
        }

        // ---- 休眠 ----
        let delay = if fail_streak > 5 { 15 } else { HEARTBEAT_SECS };
        sleep(&running, delay);
    }

    println!("\n已退出");
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

fn prompt_password(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

fn sleep(running: &Arc<AtomicBool>, secs: u64) {
    for _ in 0..secs {
        if !running.load(Ordering::SeqCst) { break; }
        std::thread::sleep(Duration::from_secs(1));
    }
}

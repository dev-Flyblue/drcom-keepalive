use std::net::{UdpSocket, TcpStream};
use std::time::Duration;
use std::process::Command;

fn ts() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

macro_rules! info { ($($a:tt)*) => { println!("[{}] [INFO] {}", ts(), format!($($a)*)) } }
macro_rules! ok   { ($($a:tt)*) => { println!("[{}] [ OK ] {}", ts(), format!($($a)*)) } }
macro_rules! fail { ($($a:tt)*) => { println!("[{}] [FAIL] {}", ts(), format!($($a)*)) } }
macro_rules! sep  { () => { println!("{}", "-".repeat(60)) } }

fn main() {
    println!("================================================================");
    println!("  校园网未认证状态 — 网络层探测");
    println!("  探测 DNS / ICMP / TCP 可达性，找隧道突破口");
    println!("================================================================\n");

    // ========== 1. DNS 探测 ==========
    sep!();
    info!("=== DNS 探测 (UDP 53) ===");
    info!("Drcom 必须放行 DNS，否则 Portal 自身无法工作\n");

    let dns_servers = &[
        ("校园 DNS (网关)", "10.254.1.38"),
        ("阿里 DNS", "223.5.5.5"),
        ("腾讯 DNS", "119.29.29.29"),
        ("Google DNS", "8.8.8.8"),
        ("Cloudflare DNS", "1.1.1.1"),
    ];

    let test_domains = &["baidu.com", "qq.com", "example.com"];

    for &(name, server) in dns_servers {
        for &domain in test_domains {
            let result = dns_query(server, domain);
            match result {
                Ok(ip) => ok!("{} ({}) → {} = {}", name, server, domain, ip),
                Err(e) => fail!("{} ({}) → {} : {}", name, server, domain, e),
            }
        }
    }

    // ========== 2. ICMP 探测 ==========
    println!();
    sep!();
    info!("=== ICMP 探测 (ping) ===");
    info!("若 ICMP 放行，可用 ptunnel/icmptunnel 隧道\n");

    let ping_targets = &[
        ("网关", "10.254.1.38"),
        ("阿里 DNS", "223.5.5.5"),
        ("百度", "110.242.68.66"),
        ("Cloudflare", "1.1.1.1"),
    ];

    for &(name, ip) in ping_targets {
        let ok_ping = ping(ip);
        if ok_ping {
            ok!("ping {} ({}) — 通", name, ip);
        } else {
            fail!("ping {} ({}) — 不通", name, ip);
        }
    }

    // ========== 3. TCP 端口探测 ==========
    println!();
    sep!();
    info!("=== TCP 端口探测 ===");
    info!("检查常见端口在未认证状态下是否可达\n");

    let tcp_targets = &[
        ("Portal HTTP", "10.254.1.38", 80),
        ("Portal ePortal", "10.254.1.38", 803),
        ("阿里 DNS TCP", "223.5.5.5", 53),
        ("Cloudflare DNS TCP", "1.1.1.1", 53),
        ("Cloudflare HTTPS", "1.1.1.1", 443),
        ("百度 HTTP", "110.242.68.66", 80),
        ("百度 HTTPS", "110.242.68.66", 443),
        ("QQ HTTP", "14.18.175.154", 80),
        ("GitHub HTTPS", "20.205.243.166", 443),
        ("SSH 常用", "1.1.1.1", 22),
    ];

    for &(name, ip, port) in tcp_targets {
        let ok_tcp = tcp_connect(ip, port);
        if ok_tcp {
            ok!("tcp {}:{} ({}) — 通", ip, port, name);
        } else {
            fail!("tcp {}:{} ({}) — 不通", ip, port, name);
        }
    }

    // ========== 4. HTTP 探测 ==========
    println!();
    sep!();
    info!("=== HTTP 探测 ===");
    info!("检查 HTTP 请求是否被重定向到 Portal\n");

    let http_targets = &[
        "http://www.baidu.com",
        "http://connect.rom.miui.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt",
    ];

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none()) // 不跟随重定向
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for &url in http_targets {
        match client.get(url).send() {
            Ok(r) => {
                let status = r.status().as_u16();
                let loc = r.headers().get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if status == 200 || status == 204 {
                    ok!("{} → {} (直通!)", url, status);
                } else if status == 302 || status == 301 {
                    if loc.contains("10.254.1.38") || loc.contains("portal") {
                        fail!("{} → {} 重定向到 Portal: {}", url, status, loc);
                    } else {
                        info!("{} → {} Location: {}", url, status, loc);
                    }
                } else {
                    info!("{} → {}", url, status);
                }
            }
            Err(e) => fail!("{} → {}", url, e),
        }
    }

    // ========== 5. 总结 ==========
    println!();
    sep!();
    info!("=== 探测总结 & 建议 ===\n");

    println!("根据上面的结果判断可用的绕过方案:");
    println!();
    println!("  DNS 通 (外部 DNS 可解析):");
    println!("    → DNS 隧道 (iodine): 最可靠，需要 VPS + 域名");
    println!("    → 安装: apt install iodine  (VPS 端)");
    println!("    → 服务端: iodined -f -c -P yourpass 172.16.0.1 t1.yourdomain.com");
    println!("    → 客户端: iodine -f -P yourpass t1.yourdomain.com");
    println!();
    println!("  ICMP 通:");
    println!("    → ICMP 隧道 (ptunnel-ng / icmptunnel)");
    println!("    → 安装: apt install ptunnel-ng  (VPS 端)");
    println!("    → 服务端: ptunnel-ng -r<VPS_IP> -R22");
    println!("    → 客户端: ptunnel-ng -p<VPS_IP> -l2222 -r<VPS_IP> -R22");
    println!();
    println!("  TCP 53 通:");
    println!("    → 在 VPS 上跑 SSH/SOCKS 监听 53 端口");
    println!("    → ssh -D 1080 -p 53 user@vps_ip");
    println!();
    println!("  TCP 443 通:");
    println!("    → 直接走 HTTPS 代理或 SSH over 443");
    println!("    → ssh -D 1080 -p 443 user@vps_ip");
    println!();
    println!("  全不通:");
    println!("    → MAC 克隆: 找到已认证用户 MAC → 修改本机 MAC");
    println!("    → arp -a 查看邻居表, 找到在线 MAC");
    println!();
    sep!();
}

/// 简易 DNS A 记录查询 (手工构造 UDP 包)
fn dns_query(server: &str, domain: &str) -> Result<String, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();

    // 构造 DNS 查询包
    let mut pkt = Vec::new();
    // Header: ID=0xABCD, QR=0, OPCODE=0, RD=1, QDCOUNT=1
    pkt.extend_from_slice(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Question: encode domain
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // end of name
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

    let addr = format!("{}:53", server);
    sock.send_to(&pkt, &addr).map_err(|e| format!("send: {}", e))?;

    let mut buf = [0u8; 512];
    let n = sock.recv(&mut buf).map_err(|e| format!("recv: {}", e))?;

    if n < 12 {
        return Err("response too short".into());
    }

    // 检查 ANCOUNT
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;
    if ancount == 0 {
        return Err("no answer".into());
    }

    // 跳过 header + question section, 找第一个 answer 的 RDATA
    // 简单方法: 从末尾往前找 4 字节的 IPv4 地址
    // Answer 的格式: NAME(2 ptr) TYPE(2) CLASS(2) TTL(4) RDLEN(2) RDATA(4 for A)
    // 从 question 末尾开始搜索
    let mut pos = 12;
    // skip question name
    while pos < n && buf[pos] != 0 {
        if buf[pos] & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += buf[pos] as usize + 1;
    }
    if pos < n && buf[pos] == 0 { pos += 1; }
    pos += 4; // QTYPE + QCLASS

    // Now at answer section
    if pos + 12 > n {
        return Err("truncated answer".into());
    }

    // Skip answer name (likely a pointer)
    if buf[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < n && buf[pos] != 0 { pos += buf[pos] as usize + 1; }
        pos += 1;
    }

    if pos + 10 > n {
        return Err("truncated".into());
    }

    let rtype = ((buf[pos] as u16) << 8) | buf[pos + 1] as u16;
    let rdlen = ((buf[pos + 8] as u16) << 8) | buf[pos + 9] as u16;
    pos += 10;

    if rtype == 1 && rdlen == 4 && pos + 4 <= n {
        Ok(format!("{}.{}.{}.{}", buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]))
    } else {
        Ok(format!("type={}, rdlen={}", rtype, rdlen))
    }
}

fn ping(target: &str) -> bool {
    Command::new("ping")
        .args(&["-n", "1", "-w", "2000", target])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tcp_connect(ip: &str, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    TcpStream::connect_timeout(
        &addr.parse().unwrap(),
        Duration::from_secs(3),
    ).is_ok()
}

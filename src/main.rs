#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unused_imports, dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Local;
use dhcproto::{v4, Decodable, Decoder, Encodable, Encoder};
use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use rand::Rng;

slint::include_modules!();

// ============================================================================

type LogBuffer = Arc<Mutex<Vec<String>>>;
type ScanFlag = Arc<AtomicBool>;

fn log(buf: &LogBuffer, msg: &str) {
    let ts = Local::now().format("%H:%M:%S");
    buf.lock().unwrap().push(format!("[{}] {}\n", ts, msg));
}

/// 服务器发现条目
#[derive(Clone)]
struct ServerEntry {
    ip: Ipv4Addr,
    mac: Option<MacAddr>,
    response_count: u32,
}

impl ServerEntry {
    fn display(&self) -> String {
        match self.mac {
            Some(mac) => format!("{}  |  {}", self.ip, mac),
            None => format!("{}  |  MAC 未解析 (响应 {} 次)", self.ip, self.response_count),
        }
    }
}

/// 复制文本到系统剪贴板
fn copy_to_clipboard(text: &str) {
    if text.is_empty() { return; }
    match arboard::Clipboard::new() {
        Ok(mut cb) => { let _ = cb.set_text(text.to_string()); }
        Err(_) => {}
    }
}

// ============================================================================
// 双通道收发：pnet 发送 + Winsock UDP:68 接收
// ============================================================================

fn open_channels(iface: &NetworkInterface) -> Result<(Box<dyn DataLinkSender>, UdpSocket), String> {
    let config = Config {
        read_timeout: Some(Duration::from_millis(50)),
        ..Config::default()
    };
    let tx = match datalink::channel(iface, config) {
        Ok(Channel::Ethernet(tx, _rx)) => tx,
        Ok(_) => return Err("不支持的通道类型".into()),
        Err(err) => return Err(format!(
            "创建底层网络接口失败：{}。\n请右键【以管理员身份运行】此程序，并确保已安装 Npcap", err
        )),
    };

    let udp_socket = match UdpSocket::bind("0.0.0.0:68") {
        Ok(s) => s,
        Err(e) => return Err(format!(
            "无法绑定 UDP 端口 68（错误:{}）。\n可能原因：\n1. 另一个程序已占用该端口\n2. 需要以管理员身份运行\n3. Windows DHCP Client 服务可能需要临时停止", e
        )),
    };
    if let Err(e) = udp_socket.set_nonblocking(true) {
        return Err(format!("设置 UDP Socket 非阻塞模式失败: {}", e));
    }

    Ok((tx, udp_socket))
}

fn recv_udp_with_timeout(socket: &UdpSocket, timeout: Duration) -> Option<(Vec<u8>, std::net::SocketAddr)> {
    let mut buf = vec![0u8; 1500];
    let start = Instant::now();
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => return Some((buf[..len].to_vec(), addr)),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => { std::thread::sleep(Duration::from_millis(5)); }
        }
    }
    None
}

// ============================================================================
// 可靠的包接收器（用于 ARP 解析）
// ============================================================================

struct PacketReceiver {
    rx: mpsc::Receiver<Vec<u8>>,
    stop_signal: Arc<AtomicBool>,
}

impl PacketReceiver {
    fn spawn(mut rx: Box<dyn pnet::datalink::DataLinkReceiver>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let (tx, ch_rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(frame) => { if tx.send(frame.to_vec()).is_err() { return; } }
                    Err(_) => { std::thread::sleep(Duration::from_millis(5)); }
                }
            }
        });
        PacketReceiver { rx: ch_rx, stop_signal: stop }
    }

    fn recv_with_timeout(&self, timeout: Duration) -> Option<Vec<u8>> {
        match self.rx.recv_timeout(timeout) {
            Ok(frame) => Some(frame),
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => None,
        }
    }
}

impl Drop for PacketReceiver {
    fn drop(&mut self) { self.stop_signal.store(true, Ordering::Relaxed); }
}

// ============================================================================
// DHCP 报文解析
// ============================================================================

struct DhcpOfferInfo {
    xid: u32,
    server_id: Option<Ipv4Addr>,
}

fn parse_dhcp_offer(dhcp_bytes: &[u8]) -> Option<DhcpOfferInfo> {
    let msg = v4::Message::decode(&mut Decoder::new(dhcp_bytes)).ok()?;
    let is_offer = matches!(
        msg.opts().get(v4::OptionCode::MessageType),
        Some(v4::DhcpOption::MessageType(v4::MessageType::Offer))
    );
    if !is_offer { return None; }
    let server_id = match msg.opts().get(v4::OptionCode::ServerIdentifier) {
        Some(v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    };
    Some(DhcpOfferInfo { xid: msg.xid(), server_id })
}

// ============================================================================
// 二层数据包构造
// ============================================================================

fn build_eth_ip_udp_frame(
    src_mac: MacAddr, dst_mac: MacAddr,
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp_buf = vec![0u8; udp_len];
    let mut udp = MutableUdpPacket::new(&mut udp_buf).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length(udp_len as u16);
    udp.set_payload(payload);
    udp.set_checksum(0); // DHCP/BOOTP: UDP checksum = 0

    let ip_len = 20 + udp_len;
    let mut ip_buf = vec![0u8; ip_len];
    let mut ip = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(ip_len as u16);
    ip.set_identification(rand::rng().random::<u16>());
    ip.set_ttl(128);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);
    ip.set_payload(&udp_buf);
    ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));

    let eth_len = 14 + ip_len;
    let mut eth_buf = vec![0u8; eth_len];
    let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv4);
    eth.set_payload(&ip_buf);

    if eth_buf.len() < 60 { eth_buf.resize(60, 0u8); }
    eth_buf
}

fn build_dhcp_message(src_mac: MacAddr, xid: u32) -> Vec<u8> {
    let chaddr = src_mac.octets().to_vec();
    let mut discover = v4::Message::new_with_id(
        xid,
        Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED,
        &chaddr,
    );
    discover.set_flags(v4::Flags::default().set_broadcast());
    discover.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));
    discover.opts_mut().insert(v4::DhcpOption::ParameterRequestList(vec![
        v4::OptionCode::SubnetMask, v4::OptionCode::Router,
        v4::OptionCode::DomainNameServer, v4::OptionCode::DomainName,
        v4::OptionCode::AddressLeaseTime, v4::OptionCode::Renewal, v4::OptionCode::Rebinding,
    ]));
    discover.opts_mut().insert(v4::DhcpOption::MaxMessageSize(1500));

    let mut dhcp_buf = Vec::new();
    let mut encoder = Encoder::new(&mut dhcp_buf);
    discover.encode(&mut encoder).expect("DHCP 编码失败");
    drop(encoder);
    dhcp_buf
}

fn build_dhcp_discover(src_mac: MacAddr, xid: u32) -> Vec<u8> {
    build_eth_ip_udp_frame(
        src_mac, MacAddr::broadcast(),
        Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST,
        68, 67,
        &build_dhcp_message(src_mac, xid),
    )
}

fn send_frame(tx: &mut Box<dyn DataLinkSender>, frame: &[u8]) -> bool {
    tx.build_and_send(1, frame.len(), &mut |buf| { buf.copy_from_slice(frame); }).is_some()
}

fn collect_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces().into_iter().filter(|i| !i.ips.is_empty() && i.mac.is_some()).collect()
}

// ============================================================================
// ARP 解析
// ============================================================================

fn build_arp_request(src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp = vec![0u8; 28];
    arp[0..2].copy_from_slice(&[0x00, 0x01]);
    arp[2..4].copy_from_slice(&[0x08, 0x00]);
    arp[4] = 6; arp[5] = 4;
    arp[6..8].copy_from_slice(&[0x00, 0x01]);
    arp[8..14].copy_from_slice(&src_mac.octets());
    arp[14..18].copy_from_slice(&src_ip.octets());
    arp[18..24].copy_from_slice(&[0u8; 6]);
    arp[24..28].copy_from_slice(&target_ip.octets());

    let mut frame = vec![0u8; 42];
    frame[0..6].copy_from_slice(&MacAddr::broadcast().octets());
    frame[6..12].copy_from_slice(&src_mac.octets());
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..42].copy_from_slice(&arp);
    frame
}

fn parse_arp_reply(eth_bytes: &[u8], target_ip: Ipv4Addr) -> Option<MacAddr> {
    let eth = EthernetPacket::new(eth_bytes)?;
    if eth.get_ethertype() != EtherTypes::Arp { return None; }
    let p = eth.payload();
    if p.len() < 28 || u16::from_be_bytes([p[6], p[7]]) != 2 { return None; }
    let mac = MacAddr::new(p[8], p[9], p[10], p[11], p[12], p[13]);
    let ip = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    if ip == target_ip { Some(mac) } else { None }
}

fn resolve_arp(
    tx: &mut Box<dyn DataLinkSender>, receiver: &PacketReceiver,
    src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let arp_frame = build_arp_request(src_mac, src_ip, target_ip);
    for _ in 1..=3 {
        if !send_frame(tx, &arp_frame) { continue; }
        let deadline = Instant::now() + Duration::from_millis(2000);
        while Instant::now() < deadline {
            if let Some(mac) = receiver.recv_with_timeout(Duration::from_millis(30))
                .and_then(|f| parse_arp_reply(&f, target_ip)) { return Some(mac); }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

// ============================================================================
// 主函数
// ============================================================================

fn main() {
    let app = AppWindow::new().unwrap();

    let log_buf: LogBuffer = Arc::new(Mutex::new(Vec::new()));
    let server_buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let scanning: ScanFlag = Arc::new(AtomicBool::new(false));

    let filtered = collect_interfaces();
    let labels: Vec<slint::SharedString> = filtered.iter()
        .map(|i| slint::SharedString::from(&format!("{} - {}", i.name, i.description)))
        .collect();
    app.set_network_interfaces(std::rc::Rc::new(slint::VecModel::from(labels)).into());

    let selected_idx: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    if let Some(first) = filtered.first() {
        if let Some(mac) = first.mac { app.set_current_mac_address(format!("{}", mac).into()); }
    }

    // ---- Timer：每 100ms 同步后台数据到 UI ----
    let log_timer = slint::Timer::default();
    {
        let log_buf = log_buf.clone();
        let scanning = scanning.clone();
        let server_buf = server_buf.clone();
        let weak = app.as_weak();
        log_timer.start(slint::TimerMode::Repeated, Duration::from_millis(100), move || {
            let Some(win) = weak.upgrade() else { return };
            win.set_is_scanning(scanning.load(Ordering::Relaxed));

            let mut msgs = log_buf.lock().unwrap();
            if !msgs.is_empty() {
                let mut text = win.get_log_text().to_string();
                for msg in msgs.drain(..) { text.push_str(&msg); }
                win.set_log_text(slint::SharedString::from(&text));
                drop(msgs);

                // 日志更新后，如果 follow-log 为 true，滚动到底部
                if win.get_follow_log() {
                    win.invoke_scroll_log_to_bottom();
                }
            }

            let mut srv = server_buf.lock().unwrap();
            if !srv.is_empty() {
                let display: String = srv.iter().cloned().collect::<Vec<_>>().join("\n");
                win.set_server_display_text(slint::SharedString::from(&display));
                srv.clear();
            }
        });
    }

    // ---- 网卡选择回调 ----
    {
        let selected_idx = selected_idx.clone();
        let filtered: Vec<(String, MacAddr)> = filtered.iter().map(|i| (
            format!("{} - {}", i.name, i.description),
            i.mac.unwrap_or(MacAddr::zero()),
        )).collect();
        let weak = app.as_weak();
        app.on_select_interface(move |value| {
            let selected = value.to_string();
            if let Some((idx, (_, mac))) = filtered.iter().enumerate().find(|(_, (name, _))| *name == selected) {
                *selected_idx.lock().unwrap() = idx;
                if let Some(win) = weak.upgrade() { win.set_current_mac_address(format!("{}", mac).into()); }
            }
        });
    }

    // ---- 复制日志到剪贴板 ----
    {
        let weak = app.as_weak();
        app.on_copy_log_text(move || {
            let text = match weak.upgrade() {
                Some(win) => win.get_log_text().to_string(),
                None => String::new(),
            };
            copy_to_clipboard(&text);
            text.into()
        });
    }

    // ---- 复制服务器列表到剪贴板 ----
    {
        let weak = app.as_weak();
        app.on_copy_server_text(move || {
            let text = match weak.upgrade() {
                Some(win) => win.get_server_display_text().to_string(),
                None => String::new(),
            };
            if text == "（暂无）" { return String::new().into(); }
            copy_to_clipboard(&text);
            text.into()
        });
    }

    // ---- 全面 DHCP 发现 ----
    {
        let log_buf = log_buf.clone();
        let server_buf = server_buf.clone();
        let scanning = scanning.clone();
        let selected_idx = selected_idx.clone();
        let ifaces: Vec<NetworkInterface> = filtered.clone();
        app.on_start_full_scan(move || {
            scanning.store(true, Ordering::Relaxed);
            let log_buf = log_buf.clone();
            let server_buf = server_buf.clone();
            let scanning = scanning.clone();
            let selected_idx = selected_idx.clone();
            let ifaces = ifaces.clone();
            std::thread::spawn(move || {
                if let Err(e) = run_full_scan(&log_buf, &server_buf, &selected_idx, &ifaces) {
                    log(&log_buf, &format!("[错误] {}", e));
                }
                log(&log_buf, "");
                log(&log_buf, "========================================");
                log(&log_buf, " 全面 DHCP 发现扫描完成");
                log(&log_buf, "========================================");
                scanning.store(false, Ordering::Relaxed);
            });
        });
    }

    // ---- 网络环路检测 ----
    {
        let log_buf = log_buf.clone();
        let scanning = scanning.clone();
        let selected_idx = selected_idx.clone();
        let ifaces: Vec<NetworkInterface> = filtered.clone();
        app.on_start_loop_test(move || {
            scanning.store(true, Ordering::Relaxed);
            let log_buf = log_buf.clone();
            let scanning = scanning.clone();
            let selected_idx = selected_idx.clone();
            let ifaces = ifaces.clone();
            std::thread::spawn(move || {
                if let Err(e) = run_loop_test(&log_buf, &selected_idx, &ifaces) {
                    log(&log_buf, &format!("[错误] {}", e));
                }
                log(&log_buf, "");
                log(&log_buf, "========================================");
                log(&log_buf, " 网络环路检测完成");
                log(&log_buf, "========================================");
                scanning.store(false, Ordering::Relaxed);
            });
        });
    }

    // ---- 清空日志 ----
    {
        let log_buf = log_buf.clone();
        let server_buf = server_buf.clone();
        let weak = app.as_weak();
        app.on_clear_logs(move || {
            log_buf.lock().unwrap().clear();
            server_buf.lock().unwrap().clear();
            if let Some(win) = weak.upgrade() {
                win.set_log_text("".into());
                win.set_server_display_text("（暂无）".into());
                win.set_follow_log(true);
            }
        });
    }

    app.run().unwrap();
}

// ============================================================================
// 阶段一+二：全面 DHCP 发现
// ============================================================================

fn run_full_scan(
    log_buf: &LogBuffer,
    server_buf: &Arc<Mutex<Vec<String>>>,
    selected_idx: &Arc<Mutex<usize>>,
    ifaces: &[NetworkInterface],
) -> Result<(), String> {
    log(log_buf, "========================================");
    log(log_buf, " 开始全面 DHCP 发现");
    log(log_buf, "========================================");

    let idx = *selected_idx.lock().unwrap();
    let iface = ifaces.get(idx).ok_or("未找到选中的网卡")?;
    let src_mac = iface.mac.ok_or("选中网卡无 MAC 地址")?;
    log(log_buf, &format!("使用网卡: {} - {}", iface.name, iface.description));
    log(log_buf, &format!("源 MAC: {}", src_mac));

    let local_ip = iface.ips.iter().find_map(|ip| match ip.ip() {
        std::net::IpAddr::V4(v) => Some(v), _ => None,
    }).unwrap_or(Ipv4Addr::UNSPECIFIED);

    let (mut tx, udp_socket) = open_channels(iface)?;

    let arp_receiver = {
        let config = Config::default();
        match datalink::channel(iface, config) {
            Ok(Channel::Ethernet(_, rx)) => PacketReceiver::spawn(rx),
            Ok(_) => return Err("不支持的网络通道类型".into()),
            Err(e) => return Err(format!("无法创建 ARP 接收通道: {}", e)),
        }
    };

    let our_xid: u32 = rand::rng().random();
    log(log_buf, &format!("本次扫描 XID: 0x{:08X}", our_xid));
    let discover_frame = build_dhcp_discover(src_mac, our_xid);

    let mut servers: HashMap<Ipv4Addr, ServerEntry> = HashMap::new();

    // ---- 阶段一：广播 DHCP 发现 ----
    log(log_buf, "");
    log(log_buf, "阶段一：广播 DHCP 服务器检测（UDP Socket 接收）");
    log(log_buf, "发送 3 次广播 DISCOVER...");
    let mut cnt_udp_recv = 0u64;

    for round in 1..=3u8 {
        log(log_buf, &format!("发送第 {} 次广播 DISCOVER...", round));
        if !send_frame(&mut tx, &discover_frame) {
            log(log_buf, "  [警告] 数据包发送失败");
        }

        let deadline = Instant::now() + Duration::from_millis(2000);
        while Instant::now() < deadline {
            if let Some((data, addr)) = recv_udp_with_timeout(&udp_socket, Duration::from_millis(50)) {
                cnt_udp_recv += 1;
                if let Some(info) = parse_dhcp_offer(&data) {
                    if info.xid != our_xid { continue; }
                    let sid = info.server_id.unwrap_or_else(|| match addr.ip() {
                        std::net::IpAddr::V4(v) => v, _ => Ipv4Addr::UNSPECIFIED,
                    });
                    log(log_buf, &format!("  发现 DHCP 服务器 -> Server ID: {} (来源: {})", sid, addr.ip()));
                    servers.entry(sid)
                        .or_insert_with(|| ServerEntry { ip: sid, mac: None, response_count: 0 })
                        .response_count += 1;
                }
            }
        }
    }

    log(log_buf, &format!("阶段一 UDP Socket 共收到 {} 个包", cnt_udp_recv));

    if servers.is_empty() {
        log(log_buf, "未发现任何 DHCP 服务器响应（广播方式）。");
    } else {
        log(log_buf, &format!("阶段一共发现 {} 个 DHCP 服务器：", servers.len()));
    }

    // ---- 阶段二：ARP 解析 + 单播 DHCP 探测 ----
    log(log_buf, "");
    log(log_buf, "阶段二：ARP 解析 + 单播 DHCP 探测（UDP Socket 接收）");

    // 收集所有需要 ARP 解析的目标：阶段一发现的服务器 IP + 常见网关
    let discovered_ips: Vec<Ipv4Addr> = servers.keys().cloned().collect();
    let common_gateways = [
        Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 2, 1), Ipv4Addr::new(192, 168, 10, 1),
        Ipv4Addr::new(192, 168, 31, 1), Ipv4Addr::new(192, 168, 50, 1),
        Ipv4Addr::new(192, 168, 100, 1), Ipv4Addr::new(192, 168, 123, 1),
        Ipv4Addr::new(192, 168, 254, 1), Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 1, 1, 1),
        Ipv4Addr::new(172, 16, 0, 1), Ipv4Addr::new(172, 16, 1, 1),
    ];

    let mut all_targets: Vec<Ipv4Addr> = discovered_ips.clone();
    for gw in &common_gateways {
        if !all_targets.contains(gw) { all_targets.push(*gw); }
    }

    for target in &all_targets {
        let is_discovered = discovered_ips.contains(target);
        log(log_buf, &format!("检查 {} ...", target));

        let target_mac = resolve_arp(&mut tx, &arp_receiver, src_mac, local_ip, *target);

        if let Some(mac) = target_mac {
            log(log_buf, &format!("  {} 在线! MAC: {}", target, mac));

            let probe_xid: u32 = rand::rng().random();
            let frame = build_eth_ip_udp_frame(
                src_mac, mac, Ipv4Addr::UNSPECIFIED, *target,
                68, 67, &build_dhcp_message(src_mac, probe_xid),
            );
            if !send_frame(&mut tx, &frame) {
                log(log_buf, "  [警告] 单播探测包发送失败"); continue;
            }
            log(log_buf, &format!("  已向 {} (MAC {}) 发送单播 DISCOVER...", target, mac));

            let deadline = Instant::now() + Duration::from_millis(3000);
            let mut got_response = false;
            while Instant::now() < deadline {
                if let Some((data, resp_addr)) = recv_udp_with_timeout(&udp_socket, Duration::from_millis(50)) {
                    if let Some(info) = parse_dhcp_offer(&data) {
                        if info.xid != probe_xid { continue; }
                        let sid = info.server_id.unwrap_or_else(|| match resp_addr.ip() {
                            std::net::IpAddr::V4(v) => v, _ => Ipv4Addr::UNSPECIFIED,
                        });
                        log(log_buf, &format!("  ✅ {} 有响应！DHCP Server ID: {}", target, sid));

                        // 更新收集表：补充 MAC 信息
                        let key = if is_discovered { *target } else { sid };
                        if let Some(entry) = servers.get_mut(&key) {
                            entry.mac = Some(mac);
                            if !is_discovered { entry.response_count += 1; }
                        } else {
                            servers.insert(key, ServerEntry { ip: key, mac: Some(mac), response_count: 1 });
                        }
                        got_response = true;
                        break;
                    }
                }
            }
            if !got_response && is_discovered {
                // 即使没响应 DHCP，也补充 MAC（ARP 成功说明设备在线）
                if let Some(entry) = servers.get_mut(target) {
                    entry.mac = Some(mac);
                }
                log(log_buf, &format!("  {} 未响应单播 DHCP，但 ARP 成功，已补充 MAC", target));
            }
            if !got_response && !is_discovered {
                log(log_buf, &format!("  {} 未响应（单播方式）", target));
            }
        } else {
            if is_discovered {
                log(log_buf, &format!("  {} ARP 解析失败，无法获取 MAC", target));
            } else {
                log(log_buf, &format!("  {} 未响应 ARP（离线或不可达）", target));
            }
        }
    }

    // ======== 最终输出：服务器列表（含 MAC 地址） ========
    if !servers.is_empty() {
        let mut list: Vec<_> = servers.values().cloned().collect();
        list.sort_by(|a, b| {
            match (&a.mac, &b.mac) {
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                _ => a.ip.cmp(&b.ip),
            }
        });

        log(log_buf, "");
        log(log_buf, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        log(log_buf, " 发现的 DHCP 服务器汇总：");
        for entry in &list {
            log(log_buf, &format!("  📡 {}", entry.display()));
        }
        log(log_buf, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // 将完整条目写入 server_buf（含 MAC 地址）
        let display_lines: Vec<String> = list.iter().map(|e| e.display()).collect();
        server_buf.lock().unwrap().extend(display_lines);
    } else {
        log(log_buf, "（未发现任何 DHCP 服务器）");
    }

    Ok(())
}

// ============================================================================
// 阶段三：二层网络环路检测
// ============================================================================

fn run_loop_test(log_buf: &LogBuffer, selected_idx: &Arc<Mutex<usize>>, ifaces: &[NetworkInterface]) -> Result<(), String> {
    log(log_buf, "========================================");
    log(log_buf, " 网络环路检测开始");
    log(log_buf, "========================================");

    let idx = *selected_idx.lock().unwrap();
    let iface = ifaces.get(idx).ok_or("未找到选中的网卡")?;
    let src_mac = iface.mac.ok_or("选中网卡无 MAC 地址")?;

    let test_xid: u32 = rand::rng().random();
    log(log_buf, &format!("环路检测专用 XID: 0x{:08X}", test_xid));

    let frame = build_dhcp_discover(src_mac, test_xid);
    let (mut tx, udp_socket) = open_channels(iface)?;
    log(log_buf, "发送单个 DHCP DISCOVER 广播...");
    if !send_frame(&mut tx, &frame) {
        log(log_buf, "  [警告] 数据包发送失败");
    }

    log(log_buf, "监听 5 秒等待 Offer（UDP Socket）...");
    let listen_start = Instant::now();
    let listen_duration = Duration::from_secs(5);
    let mut offers: Vec<Instant> = Vec::new();

    while listen_start.elapsed() < listen_duration {
        if let Some((data, _)) = recv_udp_with_timeout(&udp_socket, Duration::from_millis(30)) {
            if let Some(info) = parse_dhcp_offer(&data) {
                if info.xid != test_xid { continue; }
                offers.push(Instant::now());
                log(log_buf, &format!("  收到第 {} 个 Offer（XID: 0x{:08X}）", offers.len(), test_xid));
            }
        }
    }

    log(log_buf, "");
    log(log_buf, &format!("监听结束，共收到 {} 个匹配 Offer", offers.len()));

    if offers.len() < 2 {
        log(log_buf, "结果：未检测到网络环路（Offer 数量不足 2 个）");
    } else {
        let mut min_diff_ms = f64::MAX;
        for i in 1..offers.len() {
            let diff = offers[i].duration_since(offers[i - 1]).as_secs_f64() * 1000.0;
            if diff < min_diff_ms { min_diff_ms = diff; }
        }
        log(log_buf, &format!("最小 Offer 间隔: {:.2} ms", min_diff_ms));
        if min_diff_ms < 100.0 {
            log(log_buf, ""); log(log_buf, "!!! 检测到二层网络环路 !!!");
            log(log_buf, &format!("  - 相同 XID 收到 {} 个 DHCP Offer", offers.len()));
            log(log_buf, &format!("  - 最小间隔: {:.2} ms (< 100ms)", min_diff_ms));
            log(log_buf, "建议：检查交换机级联线路，排查冗余链路或启用 STP/RSTP。");
        } else {
            log(log_buf, "结果：未检测到网络环路");
            log(log_buf, &format!("收到 {} 个 Offer 但间隔 ≥ 100ms，正常多服务器响应", offers.len()));
        }
    }

    Ok(())
}

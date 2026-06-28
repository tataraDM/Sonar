# Sonar

Windows 局域网 DHCP 诊断工具，用 Rust + [Slint](https://slint.dev/) + [pnet](https://crates.io/crates/pnet) 构建，编译产物为单个原生 `.exe`，无运行时依赖。

## 它能做什么

针对家里 / 实验室 / 公司局域网里"上不了网"、"拿不到 IP"、"网关奇怪"这一类 DHCP 相关故障，做一次完整的链路体检：

- **阶段一 · DHCP 广播发现**：发标准 DISCOVER 监听 OFFER，把网络里所有 DHCP 服务器（包括私接路由、流讯 DHCP）列出来，带 IP / MAC / 响应次数。
- **阶段二 · 网关 ARP 单播**：对常见网关 IP 段做 ARP 解析，拿到 MAC 后用单播 DHCP 探测。这条路径绕开了 WiFi 网卡在 Managed 模式下过滤二层广播的坑,所以在无线网卡上也能正常工作。
- **阶段三 · 二层环路检测**：用随机 xid 发出单个 DISCOVER,严格禁止重传,通过收到的重复 OFFER 数量判断是否存在二层环路。

## 为什么写这个

市面上的 DHCP 工具大多是命令行,而且大部分在 WiFi 网卡上直接哑火——因为无线网卡驱动普遍会把不感兴趣的广播帧过滤掉,二层 raw socket 收不到 OFFER。Sonar 的解法是阶段二改走 ARP + 单播,绕开这个限制。

实现过程中踩过的坑不少,值得记一下:

- pnet 的 `read_timeout` 在 Windows + Npcap 下**完全不生效**,`rx.next()` 没包时无限阻塞。最终用独立后台线程 + `mpsc::recv_timeout` 解决。
- UDP 校验和按 RFC 是可选的,DHCP 实践里设 0 最稳。早期版本用 `ipv4_checksum` 算了非零值,源 IP 是 `0.0.0.0` 时伪首部边界情况导致对端 UDP 栈直接丢包。
- Slint 1.17 没有 `scrolled` 回调,但有 `flicked()`,配合一个 `follow-log` 布尔属性实现了"滚到非底部就停止自动跟随,滚回底部恢复"的智能滚动。
- Slint `Window` 没有 clipboard API,复制功能用 `TextEdit` 的 `read-only: true` 让用户直接选中复制,比加按钮干净。

## 依赖

- **Rust 1.70+**(用了 edition 2021)
- **Npcap**(Windows 上 pnet 抓包必需,装的时候勾上"Install Npcap in WinPcap API-compatible Mode")
- Slint 1.17 / pnet 0.35 / dhcproto 0.12 / rand 0.9 / chrono 0.4

## 构建

```bash
cargo build --release
# 产物在 target/release/sonar.exe
```

Release 模式下没有控制台窗口(`windows_subsystem = "windows"`),Debug 模式保留控制台方便看 `println!` 输出。

## 使用

以管理员权限运行 `sonar.exe`(raw socket 需要管理员权限),从下拉框选网卡,点"全面 DHCP 发现"。日志区会实时打印每一阶段的发现结果,服务器列表区显示阶段一/二汇总。日志和服务列表都支持直接选中文本 Ctrl+C 复制。

## 技术栈说明

- **Slint** 做 UI,纯 Rust 编译,不需要 Qt/GTK 那一堆 C++ 依赖,最终单文件 exe 体积可控。
- **pnet** 做二层 raw 收发,直接构造 Ethernet/IP/UDP 帧。
- **dhcproto** 做 DHCP 报文编解码,不用手撸 BOOTP/DHCP 二进制格式。
- 跨线程通信:`Arc<Mutex<Vec<String>>>` 装日志,`Arc<AtomicBool>` 做扫描状态,主线程 Timer 每 100ms 同步到 Slint 属性。

## 已知限制

- WiFi 网卡阶段一(广播)基本收不到 OFFER,这是驱动层过滤导致的,不是 bug。请依赖阶段二的 ARP 单播结果。
- 阶段三环路检测依赖广播路径,在 WiFi 上同样受限。
- 仅支持 IPv4 局域网。

## License

私有项目,暂不开源。

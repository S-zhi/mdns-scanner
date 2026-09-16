# mdns-scanner

<p align="left">
  <b><a href="README.md">English</a></b> |
  <b>简体中文</b>
</p>

[![Go Report Card](https://goreportcard.com/badge/github.com/S-zhi/mdns-scanner)](https://goreportcard.com/report/github.com/S-zhi/mdns-scanner)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> 基于 Go 语言开发的高性能、高并发 mDNS (Multicast / Unicast DNS-SD) 协议资产测绘与深度指纹识别命令行工具。

---

## 我们在做什么（项目背景）

在现代网络环境中（局域网、企业内网、云 VPC 及暴露在公网的网络资产），网络存储设备（如威联通 QNAP、群晖 Synology）、智能工作站、网络打印机及 IoT 物联网设备普遍默认开启 **mDNS / DNS-SD (RFC 6762 / RFC 6763)** 协议对外广播或应答自身的服务状态与硬件信息。

`mdns-scanner` 专为**网络空间测绘与资产深度发现**而设计。用户只需输入指定的目标 IP 网段（支持单 IP 或 CIDR 网段如 `192.168.1.0/24`）及探测端口范围，程序即可通过高效的单播 mDNS 探针向目标发送探测请求，并深度提取资产的完整软硬件指纹信息：
- **服务与端口绑定**：服务类型、传输层协议与服务开放端口（如 `workstation:9/tcp`、`http:5000/tcp`、`smb:445/tcp`、`afpovertcp:548/tcp` 等）。
- **主机标识**：主机域名（`*.local`）、硬件 MAC 地址、解析出的 IPv4 / IPv6 地址。
- **深度 Banner 指纹**：深度解析 TXT 记录中的元数据（设备硬件型号、系统固件版本、展示型号、访问协议、Web 路径等）。
- **DNS-SD 服务清单**：目标设备应答包含的全部 `PTR` 服务标识列表。

---

## 核心特性

- **CIDR 网段与多端口并发扫描**：支持单 IP、CIDR 网段（如 `192.168.1.0/24`）以及灵活的端口列表与范围（如 `5353`、`5000-5005`）。
- **深度元数据与指纹提取**：完整解析 `PTR`、`SRV`、`TXT`、`A` 与 `AAAA` 记录，针对空 TXT、无等号非标数据具备完备的防御性处理，绝不发生 Panic 崩溃。
- **并发 Worker Pool 架构**：内置受控的 Goroutine 工作池机制（默认 100 并发），有效防止网络 Socket 耗尽及高并发导致的丢包漏报。
- **极端网络边界防护**：完备的 UDP 静默超时熔断机制、缺失 A 记录时的自动 IP 兜底填充（Fallback）、同主机多服务去重与树状聚合。
- **标准化输出与多格式支持**：严格契合网络测绘资产格式规范的树状层级文本展示，同时支持 `--json` 输出以便下游系统集成。

---

## 架构简图

```
 [ 命令行输入参数 ] ──► ( CIDR 网段与端口解析器 )
                                │
                                ▼
                       [ 任务调度分发器 ]
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
    [ Worker 1 ]           [ Worker 2 ]          [ Worker N ] (Worker Pool 协程池)
    (单播 UDP 探测)         (单播 UDP 探测)        (单播 UDP 探测)
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │ (mDNS DNS 响应报文)
                                ▼
                       [ 聚合与解析引擎 ]
                    (SRV / TXT / PTR / A / AAAA)
                                │
                                ▼
                       [ 格式化标准输出 ]
```

---

## 快速上手

### 环境要求
- **Go 编译器**：Go 1.21 或更高版本。

### 1. 克隆代码仓库
```bash
git clone https://github.com/S-zhi/mdns-scanner.git
cd mdns-scanner
```

### 2. 编译可执行程序
```bash
go build -o mdns-scanner main.go
```

### 3. 运行扫描

#### 扫描单个 IP 的 mDNS 默认端口 (5353)
```bash
./mdns-scanner -i 192.168.1.120 -p 5353
```

#### 扫描整个 CIDR 网段
```bash
./mdns-scanner -t 192.168.1.0/24 -p 5353
```

#### 扫描指定网段与自定义端口范围，并设置并发数与超时
```bash
./mdns-scanner -t 192.168.1.0/24 -p 5353,5000-5005 -c 150 --timeout 3
```

---

## 命令行参数说明

```text
用法: mdns-scanner -t <目标> [-p <端口>] [-c <并发数>] [--timeout <秒数>] [--json]

参数选项:
  -t, --target, -i    目标 IP 或 CIDR 网段 (例如 192.168.1.0/24 或 192.168.1.120) [必选]
  -p, --port          目标端口或端口范围 (例如 5353, 5000-5005) [默认值: 5353]
  -c, --concurrency   并发工作协程数 (Worker 数量) [默认值: 100]
      --timeout       单个探测请求超时时间（秒） [默认值: 2]
      --json          以 JSON 格式输出扫描结果 [默认值: false]
```

---

## 输出示例

探测到目标网络设备（如威联通 QNAP NAS）后，程序输出如下标准格式的深度资产情报：

```text
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=192.168.1.120
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
```

---

## 自动化测试与质量保障

本项目包含全面的**表格驱动数据单元测试（Table-driven Unit Tests）**，专门针对边界场景、防御性解析、字段缺失回退及格式对齐进行自动化验证。

### 执行完整单元测试与覆盖率统计
```bash
go test -v -cover ./...
```

### 测试用例矩阵与覆盖率概览

| 代码包 Package | 测试范围与覆盖的边界场景 | 测试覆盖率 | 运行状态 |
| :--- | :--- | :---: | :---: |
| **`pkg/target`** | CIDR 流式生成、单 IP 解析、端口范围（`5000-5005`）、非法 IP/掩码越界校验（`/33`）、超限端口拦截（`70000`）。 | **80.7%** | `PASS` |
| **`pkg/parser`** | TXT 深度指纹提取、空 TXT 安全防御、无等号非标标签解析（杜绝越界 Panic）、多等号保留、缺失 A 记录时的 IP 兜底填充。 | **78.6%** | `PASS` |
| **`pkg/output`** | 完整威联通 NAS 样本格式对齐测试（精确验证 `services:`、各端口详情、Banner 属性及 `answers: PTR:`）、空指针防护。 | **80.9%** | `PASS` |
| **`pkg/probe`** | 内存级 Mock UDP mDNS 探针引擎生命周期、非阻塞响应接收、超时取消机制。 | **79.4%** | `PASS` |

详细的边界问题分析与测试用例设计方案可参阅 [DOCS/TEST_PLAN.md](DOCS/TEST_PLAN.md)。

---

## 开源协议

本项目采用 [MIT License](LICENSE) 开源许可证。

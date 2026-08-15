# Frida 动态验证：MMTLS 握手与应用数据（实测证据）

> 目标进程：Weixin.exe（PID 11268，已登录）
> 工具：Frida 17.11（Python API，持久脚本会话）
> 环境：微信 4.1.10.31，WLAN IPv6 直连微信服务器

## 1. 会话与进程状态

- 未登录状态：仅建立 :80 连接（登录页资源），**不发起 MMTLS**
- 扫码登录后：立即建立长连接
  `[2409:8a62:...]:5808 → [2409:8c54:871:3051::20]:443 ESTABLISHED`（IPv6 TCP）
- 已登录状态 attach 注入不影响微信运行（观测 2 小时+ 稳定）

## 2. 线上流量抓包（Wireshark/tshark，WLAN 接口）

60 秒窗口内 MMTLS 活跃帧（IPv6 :443）：

```
10.818407200  5808→443  391B   17 f1 04 01 82 ...   ← 客户端应用数据
10.901159800  443→5808  1231B  17 f1 04 04 ca ...   ← 服务器应用数据
12.156749500  5808→443  391B   17 f1 04 01 82 ...
18.835567200  5808→443  391B
```

- **帧格式**：`magic(3B) + length(2B BE) + 密文`
- **应用数据 magic = `17 f1 04`**，与 Go 实现 `mars/mmtls.go`
  `buildPackage([]byte{0x17, 0xf1, 0x04}, ...)` **完全一致**
- 握手包 magic 应为 `16 f1 03`（登录期未抓到，PSK 恢复直接发应用数据）

## 3. Frida hook 点与实测

### 3.1 发送层（ws2_32!send 经 IAT）

每次发送 MMTLS 帧触发（391B 心跳）：
```
[IAT] callAddr=0x7ffd860eca36 iatSlot=0x7ffd8c01a7f0 sendReal=0x7ffe96fd2320 (ws2_32!send)
[SEND] sock=0x8b0 len=391 head=17f10401826503c50be3901e2649e92102a27b21812a31d9e...
```

**调用栈**（5 帧，全部可定位）：
```
00 0x7ffd860eca3c  LongLinkWithMMTLS 发送函数（call send 返回地址）
01 0x7ffd860e7377  mars stn 长连接发送上层
02 0x7ffd818f1b16  mars stn 主循环
03 kernel32
04 ntdll
```

### 3.2 记录明文（seal 入口 0x1866c3080 的 rdx/r8）

抓到的明文记录头（mmtls2 记录格式 = `uint32 长度 + payload`）：

```
len=231  plain=000000e7 00272f6367692d62...   ← 含 "cgi-b"（HTTP/2 CGI 头）
len=370  plain=00000172 0010000100000079...
len=16   plain=00000010 080000000b010000...   ← 控制/心跳记录
len=12   plain=xxxxxxxx...（seq 计数器，末字节递增 +1/+0 交错）
```

**结论**：应用层数据在 mmtls2 内封装为 `4 字节大端长度 + 载荷`，
再经 BoringSSL AEAD 加密为 `17 f1 04` 帧。

### 3.3 nonce（seal 对象 +0x50）

每个连接方向独立 nonce（12 字节，随机）：
```
conn A: 824114912baa7715dbcfeafb
conn B: 8c9bdf73327d6c5db27fca10
```

### 3.4 GCM 底层调用链（0x342f810 hook 回溯）

```
00 0x1848ed66d/0x1848ed0f4   LongLinkWithMMTLS（发送/接收函数）
01 0x1866c31b7               mmtls2 seal 封装
02 0x186450d0b               EncryptRecord
03 0x1864506ba               （下层 GCM 状态机）
04 0x185c62621+              mmtls2 SSL 通道层
...
13 0x18111b16                mars stn
```

**三层结构**：mars stn（长连接）→ mmtls2 SSL（记录）→ BoringSSL GCM（加密）。

## 4. 关键教训（工具链）

1. **Frida MCP 的 execute 每次创建新脚本**，脚本 unload 时 Interceptor 自动
   detach——跨调用 hook 全部失效。**必须用 Python API 创建持久脚本会话**。
2. 异步 `console.log` 在 MCP 通道丢失；用 `send({t,d})` + Python 端
   `script.on('message')` 收集。
3. `NtDeviceIoControlFile` 的 IoControlCode 在 **args[5]**（args[4] 是
   IoStatusBlock 指针）——AFD_SEND=0x1201F、AFD_RECV=0x12017。
4. 微信 socket 发送最终走 `ws2_32!send`（无 IAT hook），hook 导出函数即可。
5. 未登录微信不建立 MMTLS 连接；hook 必须在登录后 attach。

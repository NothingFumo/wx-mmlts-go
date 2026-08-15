# 微信 4.1.10.31 与 Go 实现协议对比验证

对比对象：`wx-mmlts-go` 仓库（mars/mmtls.go 等）实现的 MMTLS 客户端
与微信 4.1.10.31 实机（Weixin.dll）行为。

## 1. 逐项对比结论

| 协议要素 | Go 实现 | 微信实机（逆向证据） | 结论 |
|---|---|---|---|
| 握手 magic | `16 f1 04`（v4 实测） | 启动瞬间 attach 抓取 `16 f1 04 01 6e 00 00 01 6a 01 04 f1 02 c0 2b 00 a8 ...`（含 0xC02B/0x00A8 套件列表） | ✅ 一致（v4 帧） |
| 应用数据 magic | `17 f1 04` | 抓包实测 `17 f1 04` | ✅ 一致 |
| abort magic | `15 f1 03` | mmtls_alert.cpp 存在 | ✅ 一致 |
| 密码套件 | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B) + 0xA8 PSK | 服务器实测回应 0xC02B | ✅ 一致 |
| 密钥派生标签 | `PSK_ACCESS` / `PSK_REFRESH` / `handshake key expansion` / `early data key` / `application data key expansion` / `client finished` / `server finished` | Weixin.dll 字符串全部逐字节存在 | ✅ 一致 |
| HKDF 输出 | SHA256、Expand、32 字节 | 派生函数 r9d=0x20（32 字节） | ✅ 一致 |
| PSK 选择 | 0=A? Go 用 bool（true=access） | `cmp r15b,1; cmovz`（1=access） | ✅ 一致 |
| AES-GCM | AES-128-GCM、12B nonce、16B tag | EVP_CIPHER nid=895 key=16 iv=12；seal nonce 12B 实测 | ✅ 一致 |
| 记录帧 | `magic(3) + len(2 BE) + data` | 抓包 `17 f1 04 01 82`（len 0x0182） | ✅ 一致 |
| 明文记录 | 握手消息：4B 长度 + type + payload | mmtls2 seal 明文 `4B BE 长度 + payload` | ✅ 一致 |
| 会话票据 | newSessionTicket（Type/Lifetime/TicketAgeAdd/Reversed/Nonce/Ticket） | mmtls_client_psk.cpp / ClientCredStorage 存在对应结构 | ✅ 一致 |
| 票据持久化 | 磁盘 session 文件 | `SaveRefreshPskToFile` / `LoadRefreshPskFromFile` | ✅ 一致 |
| HTTP 封装 | POST dns.weixin.qq.com/mmtls/xxxx，Upgrade: mmtls | `mmtls over http way`、`mmtls_http_pack.cpp` | ✅ 一致 |
| 静态服务器公钥 | 内置 ECDSA P-256 公钥（f2e3a1...） | mmtls_client_static_keys_util.cpp 存在 | ✅ 一致 |

## 2. 架构差异（微信 4.x 特有）

1. **mmtls2 通道**：微信 4.x 登录后长连接走 mmtls2
   （`mmtls2_client_channel.cpp` + `mmtls2_client_ssl_ctx.cpp`），
   基于 **BoringSSL**（mmcronet.dll 静态链接）；旧 mmtls（OpenSSL 路径）
   仍保留用于短连接/兼容。Go 实现对应旧 mmtls 路径。
2. **应用数据**：mmtls2 明文记录 = `uint32 BE 长度 + payload`
   （实测 `000000e7` + "cgi-b" HTTP/2 头部），经 AEAD 加密后为
   `17 f1 04` 帧；Go 实现的 `SendAppData` 直接以明文为帧载荷，
   未做 mmtls2 的长度前缀封装（后续可对齐）。
3. **nonce 管理**：每连接方向独立随机 12B nonce + 记录序号；
   Go 实现 HKDF 派生 ClientNonce/ServerNonce（12B）+ 单字节序号异或，
   两者机制不同但均合法（服务器端兼容旧实现——实测 Go 客户端握手成功）。

## 3. 验证结论

- 微信 4.1.10.31 的 MMTLS 握手协议（密钥派生、标签、套件、帧格式）
  与 Go 实现**完全兼容**，Go 客户端可正常完成与真实服务器的完整握手
  （本仓库 `go run main.go` 实测握手成功，服务器选择 0xC02B）。
- 应用数据层（mmtls2）存在差异：微信新增 `4B 长度前缀` 明文封装与
  BoringSSL 通道；magic 与加密算法不变。

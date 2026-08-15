# 微信 MMTLS 全部协议层逆向（实测版）

> 数据来源：`scripts/mmtls-handshake-capture.py` + 增强 GCM hook 的 spawn 启动期捕获
> （微信 4.1.10.31，Frida 17.11，三次独立 spawn 会话交叉验证）
> 原始数据：D:/awelogs/wx-mmtls-full2.jsonl（G=149 次 GCM 调用、P=6 组 PSK 密钥）

## 1. 帧格式（传输层）

所有 MMTLS 帧统一：`magic(3B) + length(2B BE) + 密文`

| 帧类型 | magic | 用途 | 实测证据 |
|---|---|---|---|
| 握手帧 | `16 f1 04` | ClientHello/ServerHello 等 | 启动期抓取：`16f104 016e`（len=0x16e） |
| 应用数据帧 | `17 f1 04` | 登录后长连接数据/心跳 | `17f104 0182`（391B 心跳） |
| 心跳帧 | `19 f1 04` | heartbeat | `19f104 0024` |
| 错误/关闭帧 | `15 f1 04` | alert | `15f104 0017` |

> 注：v4 协议所有 magic 第三字节为 `04`（区别于旧协议的 03）。

## 2. AEAD 认证数据（AAD）格式 —— 与 Go 实现完全一致

GCM 调用实测（0x342f810 第一连调用，d2 前 13 字节）：

```
seq(8B BE) | magic(3B) | len(2B BE)
0000000000000001 16f104 005f
0000000000000002 17f104 0020
0000000000000003 15f104 0017
```

对应 Go 实现（mars/mmtls.go `readGCMPackage`/`sendGCMPackage`）：
```go
auddit := make([]byte, 13)
binary.BigEndian.PutUint64(auddit, uint64(seq))   // 8B
copy(auddit[8:], pkt.magic)                        // 3B
binary.BigEndian.PutUint16(auddit[11:], pkt.length) // 2B
```
**逐字节一致**。

## 3. 明文记录格式（加密前）

`uint32 BE 长度 + payload`（payload 可能 zlib 压缩，0x789c 头）：

```
000000d0 000000a4 0200278d 000020c6...   握手消息明文（len=0xd0）
00000121 01052f6367692d62696e2f...       HTTP/2 请求（len=0x121）
00000010 08000000 0b010000 00060012      控制消息（len=16）
00000003 00010100 ...                    短消息（len=3）
789c3b99e6aea45d9ef6d72289...            zlib 压缩载荷
```

### 消息类型观察（len 前缀 = 消息体字节数，体首字节 = 类型）

| 类型 | 消息 | 实测样本 | 与 Go 实现对应 |
|---|---|---|---|
| 0x14 | Finished（32B 验证数据） | `00000023 14 0020 <32B HMAC>` | ✅ clientFinal `buf.WriteByte(0x14)` |
| 0x00 | 短确认消息 | `00000003 00010100` | — |
| 0x10 | 控制消息 | `00000010 00100001 00000006 ffffffff` | — |
| — | 会话票据消息（208B） | `000000d0 000000a4 0200278d 000020XX <32B random> 00000048 000c <12B nonce> <60B>` | nonce 结构已确认 |
| — | UA 扩展 | Finished 后接 `"UnifiedPCWindows 10 x86_64"` | — |

### ClientHello / 票据消息结构观察（连续缓冲，多消息拼接）

**ClientHello 片段**（len=35，type 0x14 Finished + UA 扩展）：
```
00000023 14 0020 <32B HMAC> 0699000d0080 556e6966696564504357696e646f7773203130207838365f3634
len=35  type=0x14(Finished) 32B验证数据  UA="UnifiedPCWindows 10 x86_64"
```
→ v4 ClientHello 内含 Finished 验证字段 + 客户端 UA 扩展（对应旧版扩展区）。

**会话票据消息**（len=208，2 样本差分）：
```
000000d0 000000a4 0200278d 000020de <32B random> 00000048 000c <12B nonce> <60B data>
len=208  固定164  固定      序号     随机数        子长72  nonce长12  nonce    数据
```
→ 含 nonce（12B）与高熵数据，结构对应会话票据/PSK 更新消息（mmtls_client_psk.cpp）。

**AAD 缓冲与 HKDF info 共存**：部分调用的 d2 缓冲在 AAD 帧头
（`seq+16f104+len`）后紧邻 `657870616e73696f6e`（"expansion" 标签片段）——
0x342F810 缓冲承载多数据流（AAD、明文消息、HKDF info），
确认其为 crypto util 总入口而非单一 GCM 操作。

## 4. 业务层：二进制请求格式 over MMTLS（实测修正）

> 修正：早期判断为"HTTP/2 + HPACK"有误。实测明文为**微信自定义二元请求格式**
> （cronet 传输封装），路径/主机为**明文长度前缀**，非 HPACK 编码。

帧结构：`uint32 BE 总长 | 类型(1B) | 标志(1B) | 载荷`

实测样例（启动期抓取）：

```
① GET DNS 配置请求（len=0x121, type=0x01, flags=0x05）:
00000121 01 05
2f6367692d62696e2f6d6963726f6d73672d62696e2f6e6577676574646e733f75696e3d3026636c69656e7476657273696f6e3d34303635353937393833267363656e653d35266e6574...
= /cgi-bin/micromsg-bin/newgetdns?uin=0&clientversion=4065597983&scene=5&net...

② 上报请求（len=0x247, type=0x00, 嵌套长度前缀）:
00000247 0028 2f6367692d62696e2f6d6963726f6d73672d62696e2f6e65777265706f72746b76636f6d6d727361 0018 6d696e6f7273686f72742e77656978696e2e71712e636f6d 000001ffbf92c0f2
= 00 28(路径长40) /cgi-bin/micromsg-bin/newreportkvcommrsa
  00 18(主机长24) minorshort.weixin.qq.com
  000001 ff bf 92 c0 f2（扩展字段）
```

已知 CGI：
- `/cgi-bin/micromsg-bin/newgetdns?uin=0&clientversion=4065597983&scene=5&net...`（DNS 配置）
- `/cgi-bin/micromsg-bin/newreportkvcommrsa`（KV 上报）
- 主机：`minorshort.weixin.qq.com`

## 5. 密钥派生（PSK 实测）

启动期每次握手派生两组密钥（`sub_185C691A0`，HKDF-Expand SHA256 32B）：

| mode | 标签 | 实测密钥样例 |
|---|---|---|
| 1 | PSK_ACCESS | `fe0a7be8899b35f1da92a9ff31b221ebb47ab529162071a4be53a4c308562515` |
| 2 | PSK_REFRESH | `5b74fb72d6841da37d15fbcf2a1bffbb9a4ad956b2af5f53e0f81fc0bcbacd3b` |

密钥派生标签全集（.rdata 实测）：`early data key`、`handshake key expansion`、
`PSK_ACCESS`、`PSK_REFRESH`、`application data key expansion`、
`client finished`、`server finished`——与 Go 实现逐字节一致。

## 6. 加密实现链（三层）

```
mars stn（长连接/短连接调度）
  └─ mmtls2（mmtls2_client_channel + BoringSSL SSL_CTX）
       └─ EncryptRecord（0x186450C00）→ seal（0x1866C3080）
            └─ OpenSSL EVP 封装（0x1848ED080 区，evp_enc.c）→ 0x342F810
```

### 0x342F810：crypto util 分发函数（认知修正）

0x342F810 原从 EVP_CIPHER.do_cipher 指针定位，实测为**微信 crypto util 总入口**
（mmtls_openssl_crypto_util.cpp 编译产物）：a4（第 5 参）为操作码，
数据缓冲（a2）承载多种操作：

- GCM AAD 帧头：`0000000000000001 16f104 0037 ...`（seq+magic+len）
- GCM 明文/密文：zlib 数据、长度前缀消息、高熵密文
- HKDF info 构造：缓冲尾部出现 `657870616e73696f6e`（"expansion" 标签片段）

### 方向标注（backtrace 调用者分组实测）

| 调用者 | 调用数 | 角色 |
|---|---|---|
| 0x7FFD860CD66D | 86 | 数据加解密（明文/密文在 a2 就地缓冲） |
| 0x7FFD860CCF4D | 85 | AAD 设置 + 数据（含 16f104/17f104 帧头） |
| 0x7FFD860CD0F4 | 44 | 收尾 |
| 0x7FFD860CD24B | 43 | 收尾 |

加解密共用同一分发函数，输入输出为就地缓冲（in-place），
明文与密文均可在 a2 观察。

## 7. 发送链（实测 backtrace）

```
0x18111B16（mars stn 主循环）
  └─ 0x1848D29D1 → 0x1848D5BB8 → 0x1848D780E → 0x1848D8964（LongLink 发送链）
       └─ 0x1848ED66D（发送函数，含 cs:send @ 0x18490CA36）
            └─ ws2_32!send（IAT，无 hook 替换）
```

## 8. 与 Go 库的差距清单（对齐路线）

| 层 | Go 实现 | 微信实测 | 差距 |
|---|---|---|---|
| magic | 16 f1 03 / 17 f1 04 | 16 f1 04 / 17 f1 04 | 握手帧需改 04 |
| AAD | seq8+magic3+len2 | 同左 | ✅ 无 |
| 明文记录 | 直接载荷 | 4B 长度前缀 + zlib 可选 | 需加封装 |
| 业务层 | 无 | HTTP/2 + HPACK + CGI | 需新增 |
| 密钥派生 | 同标签 | 同标签 | ✅ 无 |
| PSK 枚举 | bool | mode 1/2 | 对齐 |

## 9. 未覆盖项（诚实声明）

- 业务帧扩展字段语义（`000001ffbf92c0f2` 尾段，疑为会话/序号）
- 0-RTT early data 具体载荷
- 会话票据消息 `000000a4`/`0200278d` 固定字段语义与 60B 数据区内容
- UA 扩展前字段（`0699000d0080`）语义

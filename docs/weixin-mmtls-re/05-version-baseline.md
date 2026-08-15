# 微信 4.1.10.31 版本基线偏移表

> 用途：固定逆向基线，微信升级后可快速校验/迁移偏移。
> 基线校验：`scripts/mmtls-handshake-capture.py` 启动时自动比对 Weixin.dll MD5。

## 1. 版本信息

| 项 | 值 |
|---|---|
| 微信版本 | 4.1.10.31（FileVersion/ProductVersion 一致） |
| 安装路径 | `C:\Program Files\Tencent\Weixin\4.1.10.31\` |
| 构建时间 | 2026-06-03 21:22 |
| 编译环境 | `E:\xwechat\agent\workspace\mars_win`（mars 框架） |

## 2. 关键文件哈希

| 文件 | 大小 | MD5 |
|---|---|---|
| Weixin.dll | 183,098,416 | `6824220b1a8fd856efa6df287d91bf5e` |
| mmcronet.dll | 8,085,504 | `05b5780b89bfe385b60bd762b65d4201` |
| XNet.dll | 7,352,320 | （未记录，与 MMTLS 无关） |

## 3. Weixin.dll 关键偏移表（RVA，静态基址 0x180000000）

| 功能 | RVA | 静态地址 | 说明 |
|---|---|---|---|
| PSK 派生函数 | 0x5C691A0 | 0x185C691A0 | HKDF-Expand 派生 PSK_ACCESS/PSK_REFRESH（32B） |
| mmtls2 seal | 0x66C3080 | 0x1866C3080 | 记录加密（BoringSSL 封装），key/nonce 结构见 02 文档 |
| EncryptRecord | 0x6450C00 | 0x186450C00 | mmtls2 记录加密调度（日志 "encrypt record payload fail"） |
| 发送函数（send 调用点） | 0x490CA36 | 0x18490CA36 | `call cs:send`（IAT → ws2_32!send），rdx=密文缓冲 |
| 发送大函数入口 | 0x490B0A6 | 0x18490B0A6 | LongLinkWithMMTLS 发送路径 |
| 接收函数（recv 调用点） | 0x490CD4F | 0x18490CD4F | `call cs:recv` |

## 4. 密钥派生标签（.rdata）

| 字符串 | 静态地址 |
|---|---|
| `early data key` | 0x188D3E4B6 |
| `handshake key expansion` | 0x188D3E4CF |
| `PSK_ACCESS` | 0x188D3E678 |
| `PSK_REFRESH` | 0x188D3E69C |
| `application data key expansion` | 0x188D40486 |

## 5. 协议帧特征（实测）

| 帧 | magic | 说明 |
|---|---|---|
| 握手帧（v4） | `16 f1 04` | 启动瞬间 attach 实测抓取，含密码套件列表（0xC02B/0x00A8） |
| 应用数据帧 | `17 f1 04` | 登录后长连接心跳/数据 |
| 明文记录 | `uint32 BE 长度 + payload` | mmtls2 seal 输入（实测含 "cgi-b" HTTP/2 头） |

## 6. 版本升级迁移指引

1. 运行 `scripts/mmtls-handshake-capture.py`（自动比对 MD5）
2. MD5 不匹配 → 用文档 01/02 的定位方法重找偏移：
   - 字符串定位：扫 `PSK_ACCESS` → lea 引用 → PSK 派生函数
   - seal：从发送函数回溯（send hook → 调用栈 → EncryptRecord → seal）
3. 更新本表与脚本内 `BASELINE_MD5`/`RVAS`

# 朋友圈协议获取：收敛结论与推进路线图

## 1. 收敛结论

朋友圈协议层获取**在当前环境无法完成**，两大前置障碍：

| # | 障碍 | 现状 |
|---|---|---|
| 1 | 0x04 握手格式 | **协议层已完整逆向**（见 07 文档）：帧/AAD/明文记录/消息类型/业务格式/密钥派生/PSK 实测；握手消息（ClientHello）序号与随机数字段已确认，剩余字段语义未解析 |
| 2 | 登录态 auth key | MMTLS 匿名，业务 CGI（`/cgi-bin/micromsg-bin/`）需要登录凭证；未提取 |
| 3 | 环境不稳定 | 微信反复崩溃重启（hook 与滚动触发），无法支撑长时逆向 |

**已交付的可用成果**：
- hook 方案（渲染层实时捕获 XML、滚动驱动拉取、自动到底）
- 协议分析：MMTLS v4 架构、发送链定位、密钥派生函数与密钥实测、全协议层文档
- 抓包工具：`scripts/mmtls-handshake-capture.py`（启动瞬间 attach，实测有效）
- 数据：1669 条朋友圈（2022-03-23 ~ 2026-08-16）

## 2. 推进路线图（最小可行路径）

```
阶段 1：固定环境（已完成基线）           ← 本仓库 05-version-baseline.md
  微信 4.1.10.31 + DLL MD5 + RVA 偏移表

阶段 2：启动瞬间 attach 抓握手帧（已完成工具）
  scripts/mmtls-handshake-capture.py
  实测输出：16 f1 04 握手帧、PSK_ACCESS/PSK_REFRESH 密钥、seal 明文/nonce
  复测记录：FRAME=144/45s、PSK=84 次（spawn 后自动触发）

阶段 3：复刻 0x04 协议层（协议已逆向，Go 库对齐未完成）
  ✅ 协议层文档：docs/weixin-mmtls-re/07-full-protocol.md
     帧格式/AAD/明文记录/zlib/业务请求/密钥派生/PSK/方向标注全链路实测
  ✅ 工具：scripts/mmtls-handshake-capture.py（启动瞬间 attach，抓帧+密钥）
  ⏳ Go 库对齐：新增 0x04 模式（magic 16f104、4B 长度前缀明文封装）
  ⏳ 剩余字段：ClientHello `000000a4`/`0200278d` 语义、业务帧扩展字段、
     0-RTT early data 载荷（需稳定环境专项）
  ⚠ 需要：微信登录态（否则握手帧仅启动期 1 次）

阶段 4：提取登录态（未开始）
  定位登录凭证存储（mmtls_client_credential_storage.cpp 对应代码）
  ⚠ 需要：稳定环境 + 专项逆向时间

阶段 5：HTTP/2 over MMTLS 业务请求（未开始）
  基于 0x04 通道 + 登录态发起 /cgi-bin/micromsg-bin/ 请求
```

## 3. 关键事实记录（推进时参考）

1. **握手帧 magic 实测 `16 f1 04`**（非旧协议推断的 16 f1 03），首包载荷：
   `16 f1 04 01 6e 00 00 01 6a 01 04 f1 02 c0 2b 00 a8 58 d4 05 02 ...`
   ——含套件列表（0xC02B ECDHE、0x00A8 PSK）
2. **PSK 派生枚举**：mode=1 → PSK_ACCESS、mode=2 → PSK_REFRESH；
   密钥在输出结构 `[out+0x08]` 指向的 32 字节缓冲区
3. **登录后无握手帧**：长连接走 PSK 恢复（0-RTT 直接 `17 f1 04` 应用数据），
   握手帧只在启动/重连时出现——抓握手必须 spawn 模式
4. **明文记录格式**：`uint32 BE 长度 + payload`（mmtls2），
   与 Go 库当前 `SendAppData` 直传载荷的封装不同
5. **发送链**：mars stn → LongLinkWithMMTLS(+0x490B0A6) → `cs:send`(+0x490CA36) → ws2_32!send

## 4. 推进前置条件（新会话启动清单）

- [ ] 稳定微信环境：固定版本（基线已固化）+ 减少 hook 干扰
- [ ] 可用的登录态：建议用户保持登录，spawn 后 30 秒内完成握手抓取
- [ ] 专项时间：阶段 3/4 各需 1-2 个完整会话

# 微信登录态凭证存储（key_info.db）逆向

> 目标：`C:\Users\Lenovo\Documents\xwechat_files\all_users\login\wxid_z1g03zwfotp622\key_info.db`
> 对应实现：mmtls_client_credential_storage.cpp（ClientCredStorage）

## 1. 存储位置

```
all_users\login\<wxid>\key_info.db        # SQLite
├── LoginKeyInfoTable（56 行）
│   ├── user_name_md5  TEXT  账号 MD5（同账号恒定）
│   ├── key_md5        TEXT  （空）
│   ├── key_info_md5   TEXT  每行不同（会话版本标识）
│   └── key_info_data  BLOB  180 字节凭证
```

## 2. BLOB 结构（180 字节，4 样本差分）

```
偏移    内容                                  样本间
0x00   0a a8 01 00 0b b5 17 39 05 00 00 01 00 00 00   固定（15B）
0x0F   00 xx xx xx xx xx xx xx                         8B 随机（每行不同）
0x17   60 04 1f 20 00 64 69 20 00 00 00 6e             固定（12B）
0x23   b0 01 aa 1e 57 b6 93 70 d0 71 8d 0f 53 e0 fd   固定 31B 常量（跨行相同）
      67 21 8d f5 ca 93 32 e8 64 59 66 5d ac f4 4f e9
0x42   [高熵数据 ~96B]                                  每行不同（加密凭证）
0x??   0e 80 f1 8a 08 09 0c b0 06                      固定尾部（9B）
```

**关键观察**：
- 头部 15B 固定：`0a a8 01`（protobuf field1 len=168？）+ `00 0b` + `b5 17 39 05`（varint 时间戳候选）+ `00 00 01 00 00 00 00`
- **31B 固定常量**（0x23-0x41）：跨行相同——静态密钥/固定 nonce 候选
- 高熵区：加密的登录态凭证（key_info）
- 每行 key_info_md5 不同 → 多会话/多服务器凭证版本

## 3. 与 MMTLS 关联

- 该库对应 `mmtls_client_credential_storage.cpp`：
  `ClientCredStorage::InitPskKeys` / `SaveRefreshPskToFile` / `LoadRefreshPskFromFile`
  （RVA 0x645A25 / 0x6447A9 / 0x64562DD，见 05-version-baseline.md）
- 凭证用于 MMTLS 登录态（业务 CGI 请求的 auth 基础）
- 加密数据区解密需还原 ClientCredStorage 的加解密逻辑（登录态环境专项）

## 4. 意义

- **登录态 auth key 的落盘位置已确认**（此前路线图的阶段 4 前置）
- 登录态提取路径：hook `LoadRefreshPskFromFile`（RVA 0x64562DD）取解密后明文，
  或静态还原 ClientCredStorage 加解密

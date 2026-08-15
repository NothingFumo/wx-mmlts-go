# 微信 4.1.10.31 安装目录与 MMTLS 模块定位

> 逆向目标：`C:\Program Files\Tencent\Weixin`
> 版本：4.1.10.31（2026-06-03 构建）
> 方法：字节级特征扫描 + IDA 9.3 反汇编 + Frida 17.11 动态验证

## 1. 安装目录结构

```
C:\Program Files\Tencent\Weixin\
├── Weixin.exe              # 启动器（4.x 主程序，根目录）
├── debug.log
└── 4.1.10.31\              # 版本目录
    ├── Weixin.dll          # 183MB 主逻辑库（MMTLS 所在）
    ├── XNet.dll            # 7.3MB DNN/AI 推理库（非网络栈）
    ├── mmcronet.dll        # 8MB Cronet（BoringSSL 静态链接）
    ├── mmmojo_64.dll       # Mojo IPC
    ├── owl.dll / ilink2.dll / ilink_stream.dll / ilink_wrapper.dll
    ├── VoipEngine.dll      # 音视频引擎
    ├── RadiumWMPF.bin      # 397MB 渲染框架
    └── ...
```

## 2. 模块定位过程

### 2.1 XNet.dll 排除

字节扫描 XNet.dll 全部目标特征串均无命中；IDA 打开后字符串库显示其为
`XNet\BLAS\Device\CPU`、`XNet\DNN\XDnn*`、`XTensorShape` 等 DNN 推理库源码路径，
与网络无关。**排除**。

### 2.2 MMTLS 特征扫描（各 DLL 命中数）

| 特征串 | Weixin.dll | mmcronet.dll | XNet.dll | mmmojo_64.dll |
|---|---|---|---|---|
| `mmtls` | 264 | 0 | 0 | 0 |
| `dns.weixin.qq.com` | 5 | 0 | 0 | 0 |
| `PSK_ACCESS` | 1 | 0 | 0 | 0 |
| `PSK_REFRESH` | 1 | 0 | 0 | 0 |
| `handshake key expansion` | 1 | 0 | 0 | 0 |
| `early data key` | 1 | 0 | 0 | 0 |
| `client finished` | 6 | 1 | 0 | 0 |
| `server finished` | 4 | 1 | 0 | 0 |
| `MicroMessenger` | 6 | 0 | 0 | 0 |

**结论：MMTLS 全部实现位于 Weixin.dll**（mars_win 分支的 mmtls_lib）。
mmcronet.dll 中的 finished 串属于 Cronet 自身的 TLS 1.3 实现，与 MMTLS 无关。

### 2.3 内嵌加密库

- **OpenSSL**：Weixin.dll 内嵌（EVP 算法名表 `aes-128-gcm` 等位于
  `.rdata` 0x18846c409 附近，含 `CMAC.cmac.id-aes128-GCM...` OBJ 名表）。
- **BoringSSL**：mmcronet.dll 静态链接（仅导出 Cronet C API 435 个，
  无 crypto 导出）。

## 3. MMTLS 源码路径字符串（反编译产物）

Weixin.dll 内保留完整源码路径，证实为 **mars_win 分支的 mmtls_lib**：

```
E:\xwechat\agent\workspace\mars_win\mars\stn\src\mmtls\mmtls_lib\...
├── comm\
│   ├── mmtls_channel.cpp
│   ├── mmtls_key_pair.cpp
│   ├── mmtls_data_pack.h / mmtls_data_pack.cpp
│   ├── mmtls_data_reader.h
│   ├── mmtls_handshake_state.cpp
│   ├── mmtls_http_pack.cpp
│   ├── mmtls_ciphersuite.cpp
│   ├── mmtls_openssl_crypto_util.cpp      # OpenSSL 加密原语
│   ├── mmtls_aead_crypter_aes_gcm.cpp     # AES-GCM AEAD 加密器
│   ├── mmtls_record_writer.cpp / mmtls_record_reader.cpp
│   ├── mmtls_connection_cipher_state.cpp
│   ├── mmtls_alert.cpp
│   ├── mmtls_handshake_messages.cpp
│   ├── mmtls_extensions.cpp
│   ├── mmtls_psk.cpp
│   ├── mmtls_record_head.cpp
│   ├── mmtls_heartbeat_messages.cpp
│   └── mmtls_audit.h
├── client\
│   ├── mmtls_client_channel.cpp / mmtls_client_channel_processor.cpp
│   ├── mmtls_client_credential_manager.cpp
│   ├── mmtls_client_credential_storage.cpp
│   ├── mmtls_client_psk.cpp
│   ├── mmtls_client_static_keys_util.cpp  # 内置静态服务器公钥
│   ├── mmtls_client_handshake_state.h
│   └── client_channel\
│       ├── mmtls2_client_channel.cpp      # mmtls2（新版通道）
│       ├── mmtls2_client_ssl_ctx.cpp      # BoringSSL SSL_CTX 封装
│       ├── mmtls2_client_callback_func.cpp
│       └── mmtls2_client_session_cache.cpp / mmtls2_client_session_cache_impl.cc
└── mmtls2_client_ssl_factory.cc           # ClientSSLFactory
```

**关键结论**：
1. 微信 4.x 同时保留 **mmtls（旧）与 mmtls2（新，基于 BoringSSL SSL）** 两套实现。
2. 登录后的长连接（`17 f1 04` 应用数据）走 **mmtls2 + BoringSSL** 加密路径。
3. 密钥派生标签（`PSK_ACCESS`/`PSK_REFRESH`/`handshake key expansion`/
   `early data key`）与开源 Go 实现完全一致，证实协议未变。

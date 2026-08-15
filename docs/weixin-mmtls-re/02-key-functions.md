# MMTLS 关键函数逆向分析（Weixin.dll）

> 静态基址 0x180000000；运行时基址（ASLR）0x7ffd817e0000（本会话观察值，ASLR 每次启动可能变化）。
> 文中地址均为静态地址；运行时地址 = 静态 - 0x180000000 + 模块基址。

## 1. 密钥派生函数 `sub_185C691A0`（PSK_ACCESS / PSK_REFRESH）

**定位方法**：运行时内存扫描 `PSK_ACCESS` 字符串（0x188d3e678）→
扫描 `.text` 中 rip-relative `lea` 引用 → 命中 0x185c6930d。

**签名**：`int sub_185C691A0(MmtlsChannel* this, int mode, void* out)`
（rcx=this, edx=mode: **1=PSK_ACCESS, 2=PSK_REFRESH**（实测枚举），r8=输出结构）

**流程**（反汇编还原）：
```
r13 = r8; r15d = edx; rsi = rcx
...
cmp r15b, 1
lea rax, "PSK_ACCESS"
lea r12, "PSK_REFRESH"
cmovz r12, rax                    ; mode==1 选 PSK_ACCESS
r14 = 0x0b（标签长度 11）
[构造 HKDF info = 标签 || 握手哈希]
; 虚函数调用: [rsi+0E8h] -> vtable+0x20
; rdx = [rsi+0A8h]  （PRK 输入）
; r9d = 0x20          （输出 32 字节）
; HKDF-Expand(SHA256, key, info, 32)
```

**输出结构**（out，r8，实测 dump）：
| 偏移 | 内容 |
|---|---|
| +0x00 | 描述结构指针（含长度字段） |
| +0x08 | **32 字节密钥缓冲区指针**（PSK_ACCESS / PSK_REFRESH） |
| +0x10 | 32（长度） |

**实测密钥样例**（spawn 启动抓取）：
```
mode=1 PSK_ACCESS: f8b762dd837d0d616ab30a3238187b0335feec275087f4c0fe68bbb04fa2d0a7
mode=2 PSK_REFRESH: a504a9ffbdfba058dfbf293723f05ff7d1340a5a9e94f542fe9cf30e8b024d94
```

**与 Go 实现一致性**：
- 派生标签 `PSK_ACCESS` / `PSK_REFRESH` 逐字节一致
- 输出 32 字节一致（Go: `hkdf.Expand(sha256.New, comKey, "PSK_ACCESS"+hash, 32)`）
- 输入为握手共享密钥（comKey）与握手哈希，一致

## 2. 记录加密函数 `EncryptRecord`（0x186450c00，mmtls2 路径）

**定位方法**：GCM hook 深度回溯调用链，帧地址映射到该函数；
函数内日志字符串 `"%s \"encrypt record payload fail\""` 证实语义。

**关键逻辑**：
```
0x186450c00: push ...; sub rsp, 0x98
参数: rcx=r14(加密器), dl(标志), r8=rdi(数据), r9=rsi
r15 = [rax+8]  (rax=[rbp+80h]，数据长度?)
call sub_186452900(r14, r15, &buf)     ; 准备（AAD?）
call [rbx+38h](rbx, rsi)               ; 虚表调用（取参数）
call sub_186452AE0(r14, r15, dl, eax, &out)  ; 取密钥（输出 std::string）
call [rbx+40h](rbx, rdi, r8, r9, ...)  ; ★ seal 加密调用（虚表+0x40）
; 失败日志: "encrypt record payload fail" (0x186450d47)
```

## 3. seal 加密函数 `sub_1866C3080`（BoringSSL 封装层）

**签名**（x64 调用约定，8 参）：
```
rcx = this（加密器对象）
rdx = r12（明文指针）
r8  = r13（明文长度）
r9  = [rsp+68h]（附加参数）
[rsp+108h] = rbx（输出缓冲）
[rsp+110h] = rdi（输出长度指针）
[rsp+118h] = 输出对象（+0x10 为数据指针）
```

**对象结构**（this）：
| 偏移 | 内容 |
|---|---|
| +0x00 | vtable 指针 |
| +0x08 | 12（nonce 长度） |
| +0x10 | 16（key 长度） |
| +0x18 | 16 |
| +0x20 | 标志（==1 校验） |
| +0x30 | 输入缓冲指针（seq/计数） |
| +0x38 | 12 |
| +0x40 | 16 |
| +0x50 | **nonce 指针（12 字节）** |

**内部调用序列**：
```
call unk_1848EC750(this)      ; 创建加密上下文 r15
sub_1866C3820(r15, 16)        ; 设置 key 长度
sub_1848ECCB0(r15, 9, len, 0) ; 设置记录类型/AAD（9 = 头长?）
sub_1848ED490(r15, 0, 0, nonce_ptr)  ; 设置 nonce
sub_1848ECD80(r15, 0, &outlen, r9)   ; 执行 GCM 加密
```

## 4. 发送路径（LongLinkWithMMTLS）

```
0x184907377  <- 上层（mars stn 长连接发送）
   └─ 0x18490c900 区域（LongLinkWithMMTLS 发送函数）
       ├─ call cs:send @ 0x18490ca36   ; ★ IAT send（ws2_32）
       │    rcx = socket
       │    rdx = 密文缓冲（std::string data，含 17 f1 04 头）
       │    r8d = 长度
       └─ call cs:recv @ 0x18490cd4f   ; 接收路径
```

**关键事实**：发送走的 `cs:send` IAT 槽（0x7ffd8c01a7f0 运行时）解析为
`ws2_32!send`（0x7ffe96fd2320 运行时）——**未发现 IAT hook/替换**。

## 5. 密钥派生标签字符串（静态地址）

| 字符串 | 地址 |
|---|---|
| `early data key` | 0x188d3e4b6 |
| `handshake key expansion` | 0x188d3e4cf |
| `PSK_ACCESS` | 0x188d3e678 |
| `PSK_REFRESH` | 0x188d3e69c |
| `application data key expansion` | 0x188d40486 |

与 Go 实现（`mars/mmtls.go`）使用的标签逐字节一致。

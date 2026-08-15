#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mmtls-handshake-capture.py — 微信启动瞬间 attach 抓 MMTLS 握手帧工具

目标：在微信进程启动的最早时刻注入 hook，捕获：
  1. MMTLS 握手帧（magic 16 f1 03 / 17 f1 04 / 19 f1 03）——密文侧（ws2_32!send）
  2. PSK_ACCESS / PSK_REFRESH 派生输出（32 字节）——sub_185C691A0
     （实测 mode=1 → PSK_ACCESS，mode=2 → PSK_REFRESH；密钥在 [out+0x08] 指针）
  3. mmtls2 记录加密明文与 nonce —— sub_1866C3080（seal 封装）

版本基线（微信 4.1.10.31）：
  Weixin.dll  md5=6824220b1a8fd856efa6df287d91bf5e  size=183098416
  模块基址    ASLR（运行时自动解析）
  关键偏移（RVA，基址 + RVA = 运行时地址）：
    PSK 派生函数       0x5c691a0
    seal 封装          0x66c3080
    EncryptRecord      0x6450c00
    send 调用点(IAT)   0x490ca36（用于校验，实际 hook ws2_32!send 导出）

用法：
  python scripts/mmtls-handshake-capture.py [--timeout 120] [--out capture.jsonl]
  # 登录后握手帧出现即写入输出；超时自动退出（不杀微信）

依赖：frida（pip install frida）
"""
import argparse
import hashlib
import json
import os
import sys
import time

import frida

WEIXIN_EXE = r"C:\Program Files\Tencent\Weixin\Weixin.exe"
WEIXIN_DLL = r"C:\Program Files\Tencent\Weixin\4.1.10.31\Weixin.dll"
BASELINE_MD5 = "6824220b1a8fd856efa6df287d91bf5e"

# RVA 偏移表（微信 4.1.10.31）
RVAS = {
    "psk_derive": 0x5C691A0,   # PSK_ACCESS/PSK_REFRESH HKDF-Expand(32B)
    "seal": 0x66C3080,         # mmtls2 记录加密（BoringSSL 封装）
    "encrypt_record": 0x6450C00,
}

HOOK_JS = r"""
var RVAS = %(rvas)s;
var events = 0;
function emit(tag, d) { send({t: tag, d: d}); }
function hexstr(p, n) {
  try { var u8 = new Uint8Array(p.readByteArray(n)); var o=[];
        for (var i=0;i<n;i++) o.push(('0'+u8[i].toString(16)).slice(-2)); return o.join(''); }
  catch(e) { return 'ERR'; }
}
var installed = false;
function install() {
  var m = Process.getModuleByName('Weixin.dll');
  var base = m.base;
  emit('MODULE', {base: base.toString(), size: m.size});
  // 1) PSK 派生
  Interceptor.attach(base.add(RVAS.psk_derive), {
    onEnter: function(args) { this.mode = args[1].toInt32(); this.out = args[2]; },
    onLeave: function() {
      try {
        // 输出结构 [out+0x08] 指向 32 字节密钥缓冲区（实测确认）
        var p = this.out.add(8).readPointer();
        emit('PSK', {mode: this.mode, key: hexstr(p, 32)});
      } catch(e) { emit('PSK', {mode: this.mode, key: 'ERR ' + e}); }
    }
  });
  // 2) mmtls2 seal：key(nonce+明文)
  Interceptor.attach(base.add(RVAS.seal), {
    onEnter: function(args) {
      try {
        var self = args[0];
        var noncePtr = self.add(0x50).readPointer();
        var len = args[2].toInt32();
        emit('SEAL', {
          nonce: hexstr(noncePtr, 12),
          len: len,
          plain: (len > 0 && len <= 4096) ? hexstr(args[1], len) : ''
        });
      } catch(e) {}
    }
  });
  // 3) 密文发送帧（ws2_32!send）
  var ws2 = Process.getModuleByName('ws2_32.dll');
  Interceptor.attach(ws2.getExportByName('send'), {
    onEnter: function(args) {
      var len = args[2].toInt32();
      try {
        var m0 = args[1].readU8();
        if ((m0 === 0x16 || m0 === 0x17 || m0 === 0x19) && len >= 5) {
          emit('FRAME', {len: len, head: hexstr(args[1], Math.min(len, 48))});
        }
      } catch(e) {}
    }
  });
  installed = true;
  emit('READY', {rvas: RVAS});
}
function tryInstall() {
  try { if (!installed) install(); }
  catch(e) { setTimeout(tryInstall, 50); }
}
tryInstall();
"""


def check_baseline():
    """校验 Weixin.dll 版本基线（哈希不匹配时警告，不阻断）"""
    try:
        with open(WEIXIN_DLL, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
        ok = md5 == BASELINE_MD5
        print("[基线] Weixin.dll md5=%s %s" % (md5, "匹配 4.1.10.31" if ok else "⚠ 不匹配——偏移表可能失效"))
        return ok
    except Exception as e:
        print("[基线] 无法校验: %s" % e)
        return False


def main():
    ap = argparse.ArgumentParser(description="微信 MMTLS 握手帧捕获")
    ap.add_argument("--timeout", type=int, default=120, help="捕获时长（秒），默认 120")
    ap.add_argument("--out", default="capture.jsonl", help="输出 JSONL 路径")
    args = ap.parse_args()

    check_baseline()

    pid = None
    try:
        dev = frida.get_local_device()
        print("[spawn] 启动微信（挂起中）...")
        pid = dev.spawn([WEIXIN_EXE])
        print("[spawn] PID=%d" % pid)
        sess = dev.attach(pid)
        events = []

        def on_msg(message, data):
            if message.get("type") == "send":
                events.append(message["payload"])
            elif message.get("type") == "error":
                events.append({"t": "SCRIPT_ERR", "d": message.get("description", "")})

        script = sess.create_script(HOOK_JS % {"rvas": json.dumps(RVAS)})
        script.on("message", on_msg)
        script.load()
        print("[hook] 脚本已注入，resume 进程...")
        dev.resume(pid)

        deadline = time.time() + args.timeout
        counts = {}
        while time.time() < deadline:
            time.sleep(2)
            for e in events:
                t = e.get("t")
                if t not in counts:
                    counts[t] = 1
                    print("[%s] %s" % (t, json.dumps(e.get("d", {}), ensure_ascii=False)[:200]))
                else:
                    counts[t] += 1
            # 打印进度
            if counts.get("FRAME"):
                print("[进度] 已捕获 FRAME=%d PSK=%d SEAL=%d（剩余 %ds）"
                      % (counts.get("FRAME", 0), counts.get("PSK", 0), counts.get("SEAL", 0),
                         int(deadline - time.time())))

        with open(args.out, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        print("[完成] 事件 %d 条 → %s" % (len(events), args.out))
        print("[统计] %s" % json.dumps(counts))
        try:
            sess.detach()
        except Exception:
            pass
        print("[提示] 微信进程保持运行（PID=%d），如需退出请手动关闭" % pid)
    except KeyboardInterrupt:
        print("\n[中断] 已停止捕获")
        if pid:
            print("微信进程 PID=%d 保持运行" % pid)
    except Exception as e:
        print("[错误] %s" % e)
        sys.exit(1)


if __name__ == "__main__":
    main()

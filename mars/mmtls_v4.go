// Package mars — MMTLS v4 协议层（微信 4.x 实测逆向）
//
// 基于 docs/weixin-mmtls-re/07-full-protocol.md 的实测结果：
//   - v4 帧 magic 第三字节统一为 0x04（区别于旧版 0x03）
//   - 帧格式：magic(3B) + length(2B BE) + 密文
//   - AAD：seq(8B BE) + magic(3B) + len(2B BE)，与 v3 逐字节一致
//   - 明文记录：uint32 BE 长度 + payload（payload 可 zlib 压缩）
//
// 本文件为协议层工具（不依赖会话密钥），不改变现有 0x03 握手路径。
package mars

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
)

// v4 帧 magic（微信 4.1.10.31 实测）
var (
	MagicHandshakeV4 = []byte{0x16, 0xf1, 0x04} // 握手帧
	MagicAppV4       = []byte{0x17, 0xf1, 0x04} // 应用数据帧
	MagicHeartbeatV4 = []byte{0x19, 0xf1, 0x04} // 心跳帧
	MagicAlertV4     = []byte{0x15, 0xf1, 0x04} // 错误/关闭帧
)

// BuildAADV4 构造 13 字节 AEAD 认证数据：seq(8B BE) + magic(3B) + len(2B BE)。
// 与 v3（readGCMPackage/sendGCMPackage 的 auddit）逐字节一致。
func BuildAADV4(seq uint64, magic []byte, length uint16) []byte {
	a := make([]byte, 13)
	binary.BigEndian.PutUint64(a, seq)
	copy(a[8:], magic)
	binary.BigEndian.PutUint16(a[11:], length)
	return a
}

// PackRecordV4 封装明文记录：uint32 BE 长度 + payload（微信 mmtls2 实测格式）。
func PackRecordV4(payload []byte) []byte {
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[4:], payload)
	return buf
}

// UnpackRecordV4 解析明文记录，返回载荷与余下数据。
func UnpackRecordV4(data []byte) (payload, rest []byte, ok bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(data)
	if uint32(len(data)-4) < n {
		return nil, nil, false
	}
	return data[4 : 4+n], data[4+n:], true
}

// ZlibCompressV4 压缩载荷（微信实测明文载荷为 zlib 流，0x789c 头）。
func ZlibCompressV4(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ZlibDecompressV4 解压载荷。
func ZlibDecompressV4(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// BuildFrameV4 构造传输帧：magic(3B) + length(2B BE) + 密文。
func BuildFrameV4(magic, ciphertext []byte) []byte {
	buf := make([]byte, 5+len(ciphertext))
	copy(buf, magic)
	binary.BigEndian.PutUint16(buf[3:], uint16(len(ciphertext)))
	copy(buf[5:], ciphertext)
	return buf
}

// ParseFrameV4 解析传输帧，返回 magic、密文与余下数据。
func ParseFrameV4(data []byte) (magic, ciphertext, rest []byte, ok bool) {
	if len(data) < 5 {
		return nil, nil, nil, false
	}
	n := binary.BigEndian.Uint16(data[3:])
	if uint16(len(data)-5) < n {
		return nil, nil, nil, false
	}
	return data[:3], data[5 : 5+n], data[5+n:], true
}

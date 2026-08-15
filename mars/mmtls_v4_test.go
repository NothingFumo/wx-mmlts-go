package mars

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// 实测样本（微信 4.1.10.31 spawn 捕获，docs/weixin-mmtls-re/07-full-protocol.md）

func TestBuildAADV4(t *testing.T) {
	// 实测：seq=1, magic=16f104, len=0x5d
	got := BuildAADV4(1, MagicHandshakeV4, 0x5d)
	want, _ := hex.DecodeString("000000000000000116f104005d")
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD mismatch: got %x want %x", got, want)
	}
	// 实测：seq=2, magic=17f104, len=0x20
	got = BuildAADV4(2, MagicAppV4, 0x20)
	want, _ = hex.DecodeString("000000000000000217f1040020")
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD mismatch: got %x want %x", got, want)
	}
}

func TestPackRecordV4(t *testing.T) {
	// 实测：len=35 消息（type 0x14 Finished: 140020 + 32B HMAC = 35B）
	payload, _ := hex.DecodeString("14002016d53ee1035b8640fe18f6bde9cb4edd2aa193783f31ea970659189c4d812a13")
	if len(payload) != 35 {
		t.Fatalf("bad test payload len %d", len(payload))
	}
	got := PackRecordV4(payload)
	want, _ := hex.DecodeString("00000023" + "14002016d53ee1035b8640fe18f6bde9cb4edd2aa193783f31ea970659189c4d812a13")
	if !bytes.Equal(got, want) {
		t.Fatalf("record mismatch:\n got %x\nwant %x", got, want)
	}
	p, rest, ok := UnpackRecordV4(got)
	if !ok || !bytes.Equal(p, payload) || len(rest) != 0 {
		t.Fatalf("unpack failed: ok=%v p=%x rest=%d", ok, p, len(rest))
	}
}

func TestParseFrameV4(t *testing.T) {
	// 实测帧头：16f104 016e（len=0x16e=366）+ 2 字节占位密文
	frame := BuildFrameV4(MagicHandshakeV4, make([]byte, 366))
	magic, ct, rest, ok := ParseFrameV4(frame)
	if !ok || !bytes.Equal(magic, MagicHandshakeV4) || len(ct) != 366 || len(rest) != 0 {
		t.Fatalf("parse failed: ok=%v magic=%x ct=%d", ok, magic, len(ct))
	}
}

func TestZlibV4(t *testing.T) {
	// 实测载荷为 zlib 流（0x789c 头）
	orig := []byte("UnifiedPCWindows 10 x86_64")
	comp, err := ZlibCompressV4(orig)
	if err != nil {
		t.Fatal(err)
	}
	if len(comp) < 2 || comp[0] != 0x78 {
		t.Fatalf("not zlib header: %x", comp[:2])
	}
	back, err := ZlibDecompressV4(comp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, orig) {
		t.Fatalf("roundtrip mismatch: %q", back)
	}
}

package main

import (
	"encoding/hex"
	"encoding/binary"
	"fmt"
	"mmtls/mars"
	"os"
)

func main() {
	client := mars.NewMMTLSClient()
	if s, err := loadSession(); err == nil {
		client.Session = s
		fmt.Println("PSK 会话恢复模式")
	}
	if err := client.Handshake(); err != nil {
		fmt.Println("握手失败:", err)
		return
	}
	fmt.Println("\n[TEST] 发送 HTTP/2 preface + SETTINGS...")
	// HTTP/2 connection preface + SETTINGS 帧
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := make([]byte, 9)
	settings[3] = 0x4 // SETTINGS
	settings[4] = 0x0 // flags
	binary.BigEndian.PutUint32(settings[5:], 0) // stream 0
	resp, err := client.SendAppData(append(preface, settings...))
	if err != nil {
		fmt.Println("应用数据失败:", err)
		return
	}
	fmt.Printf("[TEST] 响应 %d 字节: %s\n", len(resp), hex.EncodeToString(resp))
}

func loadSession() (*mars.Session, error) {
	buf, err := os.ReadFile("session")
	if err != nil {
		return nil, err
	}
	return mars.LoadSession(buf)
}

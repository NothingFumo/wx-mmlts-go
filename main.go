package main

import (
	"fmt"
	"io/ioutil"
	"mmtls/mars"
	"os"

	"github.com/anonymous5l/console"
)

func SaveSessionToFile(session *mars.Session) error {
	o, err := os.OpenFile("session", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer o.Close()

	o.Write(session.SaveSession())
	return nil
}

func LoadSessionFromFile() (*mars.Session, error) {
	o, err := os.Open("session")
	if err != nil {
		return nil, err
	}
	defer o.Close()
	buf, err := ioutil.ReadAll(o)
	if err != nil {
		return nil, err
	}
	session, err := mars.LoadSession(buf)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func main() {
	fmt.Println("========================================")
	fmt.Println("微信 mmtls 协议握手程序启动")
	fmt.Println("========================================")
	fmt.Println()

	client := mars.NewMMTLSClient()

	fmt.Println("[1] 检查是否存在会话文件...")
	if session, err := LoadSessionFromFile(); err == nil {
		client.Session = session
		fmt.Println("    ✓ 找到会话文件，将使用 PSK 会话恢复模式")
	} else {
		fmt.Println("    ✓ 未找到会话文件，将进行完整握手")
	}
	fmt.Println()

	fmt.Println("[2] 开始执行 TLS 握手...")
	fmt.Println("----------------------------------------")
	if err := client.Handshake(); err != nil {
		fmt.Println()
		fmt.Println("❌ 握手失败:", err)
		console.Err("%s", err)
		return
	}
	fmt.Println("----------------------------------------")
	fmt.Println()

	fmt.Println("[3] 保存会话信息...")
	if client.Session != nil {
		if err := SaveSessionToFile(client.Session); err != nil {
			fmt.Println("    ⚠ 保存会话文件失败:", err)
		} else {
			fmt.Println("    ✓ 会话已保存到 session 文件")
		}
	}
	fmt.Println()

	fmt.Println("========================================")
	fmt.Println("✓ 握手完成！")
	fmt.Println("========================================")
}

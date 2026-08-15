package mars

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	curve = elliptic.P256()
)

type MMTLSClient struct {
	conn                                         net.Conn
	status                                       int32
	publicEcdh, verifyEcdh                       *ecdsa.PrivateKey
	serverEcdh                                   *ecdsa.PublicKey
	handshakeHasher                              hash.Hash
	handshakeReader                              io.Reader
	handshakeServerSeqNum, handshakeClientSeqNum byte
	appClientSeqNum, appServerSeqNum               uint64

	Session *Session
}

type trafficKeyPair struct {
	ClientKey   []byte
	ServerKey   []byte
	ClientNonce []byte
	ServerNonce []byte
}

func NewMMTLSClient() *MMTLSClient {
	cli := &MMTLSClient{}
	cli.handshakeHasher = sha256.New()

	cli.serverEcdh = &ecdsa.PublicKey{
		Curve: curve,
		X:     toBigIntFromHex("f2e3a105249f5628ca8a7f9264eff421752b99ff25f6c6bb560a8e207fc03b75"),
		Y:     toBigIntFromHex("dbd4c1785e6db96c149be739c7b249d0b0d3d2c9edef568f343548b68041f0f2"),
	}
	return cli
}

func (this *MMTLSClient) handshakeComplete() bool {
	return atomic.LoadInt32(&this.status) == 1
}

func (this *MMTLSClient) generalKeyPair() error {
	if this.publicEcdh == nil {
		public, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		this.publicEcdh = public
	}

	if this.verifyEcdh == nil {
		verify, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		this.verifyEcdh = verify
	}

	return nil
}

func (this *MMTLSClient) readRandom(s int) []byte {
	b := make([]byte, s)
	if n, err := rand.Read(b); err != nil {
		return nil
	} else if n != s {
		return nil
	}
	return b
}

func (this *MMTLSClient) readPackage(r io.Reader) (*mmtlsPackage, error) {
	header := make([]byte, 5)

	n, err := r.Read(header)
	if err != nil {
		return nil, err
	} else if n != len(header) {
		return nil, errors.New("data length")
	}

	pkt := deserializeHeader(header)
	pkt.data = make([]byte, pkt.length)

	offset := 0

	for uint16(offset) < pkt.length {
		n, err := r.Read(pkt.data[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
	}

	return pkt, nil
}

func (this *MMTLSClient) sendPackage(pkt *mmtlsPackage) error {
	if _, err := this.conn.Write(pkt.serialized()); err != nil {
		return err
	}
	return nil
}

func (this *MMTLSClient) computeShareKey(x, y, z *big.Int) []byte {
	r, _ := curve.ScalarMult(x, y, z.Bytes())
	s := sha256.Sum256(r.Bytes())
	return s[:]
}

func (this *MMTLSClient) earlyDataKey(pskAccess []byte, st *newSessionTicket) (*trafficKeyPair, error) {
	earlyDataHash := sha256.New()
	earlyDataHash.Write(st.export())

	trafficKey := make([]byte, 28)
	if _, err := hkdf.Expand(sha256.New, pskAccess,
		this.buildHkdfInfo("early data key expansion", earlyDataHash)).
		Read(trafficKey); err != nil {
		return nil, err
	}
	// early data key expansion
	pair := &trafficKeyPair{}
	pair.ClientKey = trafficKey[:16]
	pair.ClientNonce = trafficKey[16:]
	return pair, nil
}

func (this *MMTLSClient) trafficKey(shareKey, info []byte) (*trafficKeyPair, error) {
	trafficKey := make([]byte, 56)
	if _, err := hkdf.Expand(sha256.New, shareKey, info).Read(trafficKey); err != nil {
		return nil, err
	}
	pair := &trafficKeyPair{}
	pair.ClientKey = trafficKey[:16]
	pair.ServerKey = trafficKey[16:32]
	pair.ClientNonce = trafficKey[32:44]
	pair.ServerNonce = trafficKey[44:]
	return pair, nil
}

func (this *MMTLSClient) readGCMPackage(pkt *mmtlsPackage, keys *trafficKeyPair) (*mmtlsPackage, error) {
	c, err := aes.NewCipher(keys.ServerKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.ServerNonce)
	nonce[11] = nonce[11] ^ this.handshakeServerSeqNum
	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(this.handshakeServerSeqNum))
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)

	dst, err := aead.Open(nil, nonce, pkt.data, auddit)
	if err != nil {
		return nil, err
	}

	pkt.reset(dst)

	return pkt, nil
}

func (this *MMTLSClient) sendGCMPackage(pkt *mmtlsPackage, keys *trafficKeyPair) error {
	c, err := aes.NewCipher(keys.ClientKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	copy(nonce, keys.ClientNonce)
	nonce[11] = nonce[11] ^ this.handshakeClientSeqNum

	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, uint64(this.handshakeClientSeqNum))
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)

	pkt.reset(aead.Seal(nil, nonce, pkt.data, auddit))

	return this.sendPackage(pkt)
}

func (this *MMTLSClient) verifyEcdsa(data []byte) bool {
	dataHash := sha256.Sum256(this.handshakeHasher.Sum(nil))
	return ecdsa.VerifyASN1(this.serverEcdh, dataHash[:], data)
}

func (this *MMTLSClient) buildHkdfInfo(prefix string, hash hash.Hash) []byte {
	info := []byte(prefix)
	if hash != nil {
		info = append(info, hash.Sum(nil)...)
	}
	return info
}

func (this *MMTLSClient) hmac(k, d []byte) []byte {
	hm := hmac.New(sha256.New, k)
	hm.Write(d)
	return hm.Sum(nil)
}

func (this *MMTLSClient) clientFinal(comKey []byte, keyPair *trafficKeyPair) error {
	cliKey := make([]byte, 32)
	if _, err := hkdf.Expand(sha256.New, comKey,
		this.buildHkdfInfo("client finished",
			nil)).Read(cliKey); err != nil {
		return err
	}
	cliKey = this.hmac(cliKey, this.handshakeHasher.Sum(nil))

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.BigEndian, uint32(3+len(cliKey))); err != nil {
		return err
	}
	buf.WriteByte(0x14)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(cliKey))); err != nil {
		return err
	}
	buf.Write(cliKey)

	pkt := buildPackage(magicHandshake, buf.Bytes())

	if err := this.sendGCMPackage(pkt, keyPair); err != nil {
		return err
	}

	this.handshakeClientSeqNum++
	return nil
}

func (this *MMTLSClient) reset() {
	this.handshakeHasher.Reset()
	this.handshakeClientSeqNum = 0
	this.handshakeServerSeqNum = 0
}

func (this *MMTLSClient) buildRequestHeader(cl int64) ([]byte, error) {
	request := &http.Request{
		Method:     http.MethodPost,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     map[string][]string{},
	}

	randName := make([]byte, 4)
	if _, err := rand.Read(randName); err != nil {
		return nil, err
	}

	request.Header.Set("Accept", "*/*")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", cl))
	request.Header.Set("Upgrade", "mmtls")
	request.Header.Set("User-Agent", "MicroMessenger Client")
	request.URL, _ = url.Parse(fmt.Sprintf("https://dns.weixin.qq.com/mmtls/%x", randName))

	b, err := httputil.DumpRequest(request, false)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (this *MMTLSClient) Handshake() error {
	fmt.Println("  [2.1] 建立 TCP 连接...")
	if this.conn == nil {
		fmt.Println("        → 连接到 dns.weixin.qq.com:443")
		conn, err := net.Dial("tcp", "dns.weixin.qq.com:443")
		if err != nil {
			fmt.Println("        ❌ 连接失败:", err)
			return err
		}
		this.conn = conn
		fmt.Println("        ✓ TCP 连接已建立")
	} else {
		fmt.Println("        ✓ 使用已有连接")
	}

	if !this.handshakeComplete() {
		fmt.Println()
		fmt.Println("  [2.2] 重置握手状态...")
		this.reset()
		fmt.Println("        ✓ 握手状态已重置")

		fmt.Println()
		fmt.Println("  [2.3] 生成密钥对...")
		if err := this.generalKeyPair(); err != nil {
			fmt.Println("        ❌ 生成密钥对失败:", err)
			return err
		}
		fmt.Println("        ✓ ECDH 公钥密钥对已生成")
		fmt.Println("        ✓ ECDH 验证密钥对已生成")

		fmt.Println()
		fmt.Println("  [2.4] 构建 ClientHello 消息...")
		ch := &clientHello{}
		ch.Timestamp = uint32(time.Now().Unix())
		ch.Random = this.readRandom(32)
		fmt.Printf("        → 时间戳: %d\n", ch.Timestamp)
		fmt.Printf("        → 随机数: %d 字节\n", len(ch.Random))
		
		// 1-RTT ECDHE, 1-RTT PSK, 0-RTT PSK
		if this.Session != nil {
			// INAN 0x00 0xA8 TLS_PSK_WITH_AES_128_GCM_SHA256
			ch.CipherSuite = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xa8}
			ch.Count = 2
			ch.Extension = append(ch.Extension, pskExtension(this.Session.tk.Tickets[1]))
			fmt.Println("        → 密码套件: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_PSK_WITH_AES_128_GCM_SHA256 (PSK)")
			fmt.Println("        → 模式: PSK 会话恢复 (0-RTT)")
		} else {
			ch.Count = 1
			ch.CipherSuite = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			fmt.Println("        → 密码套件: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
			fmt.Println("        → 模式: 完整握手 (1-RTT ECDHE)")
		}
		ch.Extension = append(ch.Extension, append(ecdsaExtension([]ecdsa.PublicKey{
			this.publicEcdh.PublicKey,
			this.verifyEcdh.PublicKey,
		}), 0x00, 0x00, 0x00, 0x01))
		fmt.Println("        → ECDSA 扩展已添加")

		fmt.Println()
		fmt.Println("  [2.5] 发送 ClientHello 消息...")
		if err := this.clientHello(ch); err != nil {
			fmt.Println("        ❌ 发送失败:", err)
			return err
		}
		fmt.Println("        ✓ ClientHello 已发送")

		fmt.Println()
		fmt.Println("  [2.6] 接收并解析 ServerHello...")
		serverHello, err := this.readServerHello()
		if err != nil {
			fmt.Println("        ❌ 接收失败:", err)
			return err
		}
		fmt.Printf("        ✓ ServerHello 已接收\n")
		fmt.Printf("        → 密码套件: 0x%04x\n", serverHello.CipherSuite)
		fmt.Println("        → 服务器公钥已提取")

		fmt.Println()
		fmt.Println("  [2.7] 计算共享密钥 (ECDH)...")
		// DH compute key
		comKey := this.computeShareKey(serverHello.PublicKey.X, serverHello.PublicKey.Y, this.publicEcdh.D)
		fmt.Printf("        ✓ 共享密钥已计算 (长度: %d 字节)\n", len(comKey))

		fmt.Println()
		fmt.Println("  [2.8] 派生握手流量密钥...")
		// traffic keys
		trafficKey, err := this.trafficKey(comKey,
			this.buildHkdfInfo("handshake key expansion", this.handshakeHasher))

		if err != nil {
			fmt.Println("        ❌ 派生失败:", err)
			return err
		}
		fmt.Println("        ✓ 握手加密密钥已派生")
		fmt.Println("        → 客户端密钥、服务器密钥、nonce 已生成")

		fmt.Println()
		fmt.Println("  [2.9] 接收服务器签名...")
		// compare traffic key is valid
		signature, err := this.readSignature(trafficKey)
		if err != nil {
			fmt.Println("        ❌ 接收失败:", err)
			return err
		}
		fmt.Printf("        ✓ 签名已接收 (类型: 0x%02x, 长度: %d 字节)\n", signature.Type, len(signature.EcdsaSignature))

		fmt.Println()
		fmt.Println("  [2.10] 验证服务器签名...")
		if !this.verifyEcdsa(signature.EcdsaSignature) {
			fmt.Println("        ❌ 签名验证失败")
			return errors.New("verify signature failed")
		}
		fmt.Println("        ✓ 签名验证通过")

		sData := signature.serialized()
		this.handshakeHasher.Write(sData)

		fmt.Println()
		fmt.Println("  [2.11] 接收会话票据 (NewSessionTicket)...")
		// for not don't process
		// example: for next usage save information to local storage
		ex, err := this.readNewSessionTicket(trafficKey)
		if err != nil {
			fmt.Println("        ❌ 接收失败:", err)
			return err
		}
		fmt.Printf("        ✓ 会话票据已接收 (票据数量: %d)\n", len(ex.Tickets))
		if len(ex.Tickets) > 0 {
			fmt.Printf("        → 票据生命周期: %d 秒\n", ex.Tickets[0].TicketLifeTime)
		}

		fmt.Println()
		fmt.Println("  [2.12] 派生 PSK 访问密钥...")
		pskAccess := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("PSK_ACCESS",
				this.handshakeHasher)).Read(pskAccess); err != nil {
			fmt.Println("        ❌ 派生失败:", err)
			return err
		}
		fmt.Println("        ✓ PSK_ACCESS 密钥已派生")

		// for next psk key update time one mouth
		fmt.Println()
		fmt.Println("  [2.13] 派生 PSK 刷新密钥...")
		pskRefresh := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("PSK_REFRESH",
				this.handshakeHasher)).Read(pskRefresh); err != nil {
			fmt.Println("        ❌ 派生失败:", err)
			return err
		}
		fmt.Println("        ✓ PSK_REFRESH 密钥已派生")

		fmt.Println()
		fmt.Println("  [2.14] 接收 ServerFinished...")
		sf, err := this.readServerFinish(trafficKey)
		if err != nil {
			fmt.Println("        ❌ 接收失败:", err)
			return err
		}
		fmt.Println("        ✓ ServerFinished 已接收")

		fmt.Println()
		fmt.Println("  [2.15] 验证 ServerFinished...")
		sfKey := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("server finished",
				nil)).Read(sfKey); err != nil {
			fmt.Println("        ❌ 派生验证密钥失败:", err)
			return err
		}

		securityParam := this.hmac(sfKey, this.handshakeHasher.Sum(nil))

		if bytes.Compare(sf.Data, securityParam) != 0 {
			fmt.Println("        ❌ ServerFinished 验证失败")
			return errors.New("security key not compare")
		}
		fmt.Println("        ✓ ServerFinished 验证通过")

		// local store cache
		//ex.exportWithPskRefresh(pskRefresh)

		fmt.Println()
		fmt.Println("  [2.16] 发送 ClientFinished...")
		if err := this.clientFinal(comKey, trafficKey); err != nil {
			fmt.Println("        ❌ 发送失败:", err)
			return err
		}
		fmt.Println("        ✓ ClientFinished 已发送")

		fmt.Println()
		fmt.Println("  [2.17] 派生应用数据密钥...")
		expandedSecret := make([]byte, 32)
		if _, err := hkdf.Expand(sha256.New, comKey,
			this.buildHkdfInfo("expanded secret",
				this.handshakeHasher)).Read(expandedSecret); err != nil {
			fmt.Println("        ❌ 派生扩展密钥失败:", err)
			return err
		}

		keyExchange, err := this.trafficKey(expandedSecret,
			this.buildHkdfInfo("application data key expansion",
				this.handshakeHasher))
		if err != nil {
			fmt.Println("        ❌ 派生应用密钥失败:", err)
			return err
		}
		fmt.Println("        ✓ 应用数据加密密钥已派生")

		fmt.Println()
		fmt.Println("  [2.18] 派生早期数据密钥...")
		earlyPair, err := this.earlyDataKey(pskAccess, ex)
		if err != nil {
			fmt.Println("        ❌ 派生早期数据密钥失败:", err)
			return err
		}
		fmt.Println("        ✓ 早期数据密钥已派生")

		fmt.Println()
		fmt.Println("  [2.19] 保存会话信息...")
		// set psk session
		if this.Session == nil {
			this.Session = &Session{
				tk:             ex,
				PskAccess:      pskAccess,
				earlyKey:       earlyPair,
				applicationKey: keyExchange,
			}
			fmt.Println("        ✓ 新会话已创建")
		} else {
			// PSK 恢复模式：更新应用数据密钥（每次握手重新派生）
			this.Session.tk = ex
			this.Session.PskAccess = pskAccess
			this.Session.earlyKey = earlyPair
			this.Session.applicationKey = keyExchange
			fmt.Println("        ✓ 使用已有会话 (应用密钥已更新)")
		}

		// fully complete handshake
		atomic.StoreInt32(&this.status, 1)
		fmt.Println()
		fmt.Println("  [2.20] ✓ TLS 握手已完成！")
	}

	return nil
}

// sendAppGCM 应用层加密发送（独立序列号）
func (this *MMTLSClient) sendAppGCM(pkt *mmtlsPackage) error {
	c, err := aes.NewCipher(this.Session.applicationKey.ClientKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	copy(nonce, this.Session.applicationKey.ClientNonce)
	nonce[11] = nonce[11] ^ byte(this.appClientSeqNum)
	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, this.appClientSeqNum)
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)
	pkt.reset(aead.Seal(nil, nonce, pkt.data, auddit))
	if err := this.sendPackage(pkt); err != nil {
		return err
	}
	this.appClientSeqNum++
	return nil
}

// readAppGCM 应用层解密读取（独立序列号）
func (this *MMTLSClient) readAppGCM(pkt *mmtlsPackage) ([]byte, error) {
	c, err := aes.NewCipher(this.Session.applicationKey.ServerKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce, this.Session.applicationKey.ServerNonce)
	nonce[11] = nonce[11] ^ byte(this.appServerSeqNum)
	auddit := make([]byte, 13)
	binary.BigEndian.PutUint64(auddit, this.appServerSeqNum)
	copy(auddit[8:], pkt.magic)
	binary.BigEndian.PutUint16(auddit[11:], pkt.length)
	dst, err := aead.Open(nil, nonce, pkt.data, auddit)
	if err != nil {
		return nil, err
	}
	this.appServerSeqNum++
	return dst, nil
}

// SendAppData 发送应用数据（magic 0x17）并读取响应（实验性）
func (this *MMTLSClient) SendAppData(plaintext []byte) ([]byte, error) {
	if !this.handshakeComplete() {
		return nil, fmt.Errorf("handshake not complete")
	}
	pkt := buildPackage([]byte{0x17, 0xf1, 0x04}, plaintext)
	if err := this.sendAppGCM(pkt); err != nil {
		return nil, err
	}
	resp, err := this.readPackage(this.conn)
	if err != nil {
		return nil, err
	}
	fmt.Printf("  [APP-RESP] magic=%x len=%d\n", resp.magic, resp.length)
	if resp.magic[0] == 0x16 || resp.magic[0] == 0x19 {
		return resp.data, nil
	}
	dec, err := this.readAppGCM(resp)
	if err != nil {
		return nil, fmt.Errorf("decrypt fail: %v (raw=%x)", err, resp.data[:min(64, len(resp.data))])
	}
	return dec, nil
}

func min(a, b int) int { if a < b { return a }; return b }

package main

import (
	"bytes"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"os/exec"
	"strings"
)

// VPNConfig はRPCに送信するVPN設定情報
type VPNConfig struct {
	Password      string
	Interface     string
	PrivateKey    string
	Address       string
	PeerPublicKey string
	PeerEndpoint  string
}

// サーバー側の公開鍵 VPN情報 事前共有鍵を受け取る
type VPNResponse struct {
	ServerPublicKey string
	ServerPresharedKey string
	ServerAddress   string
	Message         string
}

// 外部コマンドを実行し、出力を返す
func execCommand(name string, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// WireGuardの秘密鍵と対応する公開鍵を生成
func generateKeyPair() (privateKey, publicKey string, err error) {
	privKey, err := execCommand("wg", "genkey")
	if err != nil {
		return "", "", err
	}

	pubKeyCmd := exec.Command("wg", "pubkey")
	pubKeyCmd.Stdin = strings.NewReader(privKey)
	var pubKeyOut bytes.Buffer
	pubKeyCmd.Stdout = &pubKeyOut
	err = pubKeyCmd.Run()
	if err != nil {
		return "", "", err
	}

	return privKey, strings.TrimSpace(pubKeyOut.String()), nil
}

func main() {
	client, err := rpc.Dial("tcp", "WgSrvIP:50000")
	if err != nil {
		log.Fatal("Connection error:", err)
	}
	defer client.Close()

	// WireGuardの鍵ペアを生成
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		log.Fatal("Key generation error:", err)
	}

	// VPN設定を送信
	config := VPNConfig{
		Password:      "securepassword",
		Interface:     "wg1",
		PrivateKey:    privateKey,
		Address:       "10.0.0.2/24",
		PeerPublicKey: publicKey, // クライアントの公開鍵を送信
		PeerEndpoint:  "WgSrvIP:51820",
	}

	var response VPNResponse
	err = client.Call("WireGuardService.SetupVPN", config, &response)
	if err != nil {
		log.Fatal("RPC error:", err)
	}

	// クライアント側の設定ファイルを生成
	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = 8.8.8.8

[Peer]
PublicKey = %s
PreSharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, privateKey, config.Address, response.ServerPublicKey, response.ServerPresharedKey, config.PeerEndpoint)

	err = os.WriteFile(fmt.Sprintf("/etc/wireguard/%s.conf", config.Interface), []byte(clientConfig), 0600)
	if err != nil {
		log.Fatal("Failed to write client config:", err)
	}

	// VPNを起動
	exec.Command("wg-quick", "up", config.Interface).Run()

	fmt.Println("VPN setup complete!")
}


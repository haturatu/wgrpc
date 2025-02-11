package main

import (
        "bytes"
        "errors"
        "fmt"
        "log"
        "net"
        "net/rpc"
        "os"
        "os/exec"
        "strings"
        "sync"
)

// VPNConfig はRPCで受け取るVPN設定情報
type VPNConfig struct {
        Password      string
        Interface     string
        PrivateKey    string
        Address       string
        PeerPublicKey string
        PeerEndpoint  string
        PreSharedKey  string
}

// VPNResponse はサーバー側で生成した公開鍵 VPN情報 事前共通鍵を返す
type VPNResponse struct {
        ServerPublicKey string
        ServerPresharedKey string
        ServerAddress   string
        Message         string
}

// RPCでVPN設定を受け付けるサービス
type WireGuardService struct {
        mu       sync.Mutex
        authPass string
}

// 認証用パスワードを設定
func NewWireGuardService(password string) *WireGuardService {
        return &WireGuardService{authPass: password}
}

// 秘密鍵・公開鍵を生成
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

func generatePreSharedKey() (string, error) {
        return execCommand("wg", "genpsk")
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

// VPNをセットアップする
func (w *WireGuardService) SetupVPN(config VPNConfig, reply *VPNResponse) error {
        w.mu.Lock()
        defer w.mu.Unlock()

        // 認証
        if config.Password != w.authPass {
                return errors.New("authentication failed")
        }

        // サーバー側の鍵ペアを生成
        serverPrivateKey, serverPublicKey, err := generateKeyPair()
        if err != nil {
                return err
        }

        // 事前共有鍵を生成
        preSharedKey, err := generatePreSharedKey()
        if err != nil {
                return err
        }

        serverAddress := "20.0.0.1/24" // サーバー側の固定アドレス

        // WireGuardの設定ファイルを作成
        wgConfig := fmt.Sprintf(`[Interface]
ListenPort = 51820
PrivateKey = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, serverPrivateKey, config.PeerPublicKey, preSharedKey, config.Address)

        wgFile := fmt.Sprintf("/usr/local/etc/wireguard/%s.conf", config.Interface)
        err = os.WriteFile(wgFile, []byte(wgConfig), 0600)
        if err != nil {
                return err
        }

        // WireGuardを起動
        cmd := exec.Command("wg-quick", "up", config.Interface)
        err = cmd.Run()
        if err != nil {
                return err
        }

        // クライアントにサーバーの公開鍵と事前共有鍵を返す
        *reply = VPNResponse{
                ServerPublicKey: serverPublicKey,
                ServerPresharedKey: preSharedKey,
                ServerAddress:   serverAddress,
                Message:         "VPN setup complete",
        }

        return nil
}

func main() {
        rpcServer := rpc.NewServer()
				// Todo : 認証方法は要検討
        service := NewWireGuardService("securepassword") // 認証パスワードを設定
        rpcServer.Register(service)

        listener, err := net.Listen("tcp", ":50000")
        if err != nil {
                log.Fatal("Failed to start server:", err)
        }
        defer listener.Close()

        log.Println("WireGuard RPC Server started on port 50000")
        for {
                conn, err := listener.Accept()
                if err != nil {
                        log.Println("Connection error:", err)
                        continue
                }
                go rpcServer.ServeConn(conn)
        }
}



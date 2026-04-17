package vapid

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	webpush "github.com/SherClockHolmes/webpush-go"
)

const (
	publicKeyFile  = "server-vapid.pub"
	privateKeyFile = "server-vapid.priv"
)

// KeyPair stores the server VAPID keys.
type KeyPair struct {
	Public  string
	Private string
}

// LoadOrGenerate loads VAPID keys from disk or generates and persists them.
func LoadOrGenerate(dataDir string) (KeyPair, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return KeyPair{}, fmt.Errorf("vapid: mkdir %s: %w", dataDir, err)
	}

	pubPath := filepath.Join(dataDir, publicKeyFile)
	privPath := filepath.Join(dataDir, privateKeyFile)

	pubBytes, pubErr := os.ReadFile(pubPath)
	privBytes, privErr := os.ReadFile(privPath)
	if pubErr == nil && privErr == nil {
		log.Println("push: loaded VAPID keys from disk")
		return KeyPair{
			Public:  string(pubBytes),
			Private: string(privBytes),
		}, nil
	}

	privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return KeyPair{}, fmt.Errorf("vapid: generate VAPID keys: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(publicKey), 0o644); err != nil {
		return KeyPair{}, fmt.Errorf("vapid: write public key: %w", err)
	}
	if err := os.WriteFile(privPath, []byte(privateKey), 0o600); err != nil {
		return KeyPair{}, fmt.Errorf("vapid: write private key: %w", err)
	}

	log.Println("push: generated new VAPID keys")
	return KeyPair{
		Public:  publicKey,
		Private: privateKey,
	}, nil
}

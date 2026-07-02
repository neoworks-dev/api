package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type KeyManager struct {
    mu         sync.RWMutex
    privateKey *ecdsa.PrivateKey
    keySet     jwk.Set
    keyID      string
}


func NewKeyManager(keyPath string) (*KeyManager, error) {
    // Prefer environment variable in production
    if pem := os.Getenv("AUTH_PRIVATE_KEY"); pem != "" {
        key, err := parseKeyFromPEM([]byte(pem))
        if err != nil {
            return nil, err
        }
        km := &KeyManager{privateKey: key, keyID: "neoworks-auth-v1"}
        return km, km.buildKeySet()
    }

    // Fall back to file (dev only)
    var privateKey *ecdsa.PrivateKey

    if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
        key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {
            return nil, err
        }
        if err := persistKey(key, keyPath); err != nil {
            return nil, err
        }
        privateKey = key
    } else {
        key, err := loadKey(keyPath)
        if err != nil {
            return nil, err
        }
        privateKey = key
    }

    km := &KeyManager{
        privateKey: privateKey,
        keyID:      "neoworks-auth-v1",
    }
    if err := km.buildKeySet(); err != nil {
        return nil, err
    }
    return km, nil
}

func parseKeyFromPEM(data []byte) (*ecdsa.PrivateKey, error) {
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, errors.New("failed to decode PEM block")
    }
    return x509.ParseECPrivateKey(block.Bytes)
}

func (km *KeyManager) PrivateKey() *ecdsa.PrivateKey {
    km.mu.RLock()
    defer km.mu.RUnlock()
    return km.privateKey
}

// JWKSJson returns the public JWKS as raw JSON for the /.well-known/jwks.json endpoint
func (km *KeyManager) JWKSJson() ([]byte, error) {
    km.mu.RLock()
    defer km.mu.RUnlock()
    return json.Marshal(km.keySet)
}

func (km *KeyManager) buildKeySet() error {
    key, err := jwk.FromRaw(km.privateKey.Public())
    if err != nil {
        return err
    }
    if err := key.Set(jwk.KeyIDKey, km.keyID); err != nil {
        return err
    }
    if err := key.Set(jwk.AlgorithmKey, jwt.SigningMethodES256.Alg()); err != nil {
        return err
    }
    if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
        return err
    }
    set := jwk.NewSet()
    if err := set.AddKey(key); err != nil {
        return err
    }
    km.keySet = set
    return nil
}

func persistKey(key *ecdsa.PrivateKey, path string) error {
    der, err := x509.MarshalECPrivateKey(key)
    if err != nil {
        return err
    }
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    defer f.Close()
    return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, errors.New("failed to decode PEM block")
    }
    return x509.ParseECPrivateKey(block.Bytes)
}
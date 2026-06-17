package security

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const CurveSize = 32
const SymKeySize = 32

var salt = make([]byte, 16)
var info = []byte("session")

func DeriveSymmetricKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	h := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, SymKeySize)
	if _, err := io.ReadFull(h, key[:]); err != nil {
		return nil, fmt.Errorf("read HKDF key: %w", err)
	}
	return key, nil
}

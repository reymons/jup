package security

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const NonceSize = 12

const AuthTagSize = 16

func GetCipher(key []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return gcm, nil
}

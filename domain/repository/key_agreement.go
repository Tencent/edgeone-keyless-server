package repository

import (
	"context"
	"crypto"
	"crypto/tls"
	// mytls "git.woa.com/johnnyqchen/mutual_https/thirdlib/cfssl/crypto/tls"
)

// KeyAgreement is define the key agreement interface.
type KeyAgreement interface {
	// Encrypt encrypts the data.
	Encrypt(ctx context.Context, ciphertext []byte, config *tls.Config, privateKey *crypto.PrivateKey,
		padding int) ([]byte, error)
	// Decrypt decrypts the data.
	Decrypt(ctx context.Context, ciphertext []byte, config *tls.Config, privateKey *crypto.PrivateKey,
		padding int) ([]byte, error)
	// Sign signs the data.
	Sign(ctx context.Context, ciphertext []byte, config *tls.Config, privateKey *crypto.PrivateKey, pss bool) ([]byte,
		error)
}

package entity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"

	response "edgeone-keyless-server/infrastructure/constant"

	"trpc.group/trpc-go/trpc-go/log"
)

// EccKeyAgreement implements repository.KeyAgreement.
type EccKeyAgreement struct {
	// Hash func(version uint16, macKey []byte) macFunction
	Version uint16
	SigType crypto.Hash
}

// Decrypt implements repository.KeyAgreement.
func (e EccKeyAgreement) Decrypt(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, padding int,
) ([]byte, error) {
	panic("unimplemented")
}

// Encrypt implements repository.KeyAgreement.
func (e EccKeyAgreement) Encrypt(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, padding int,
) ([]byte, error) {
	panic("unimplemented")
}

// Sign implements repository.KeyAgreement.
func (e EccKeyAgreement) Sign(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, pss bool,
) (out []byte, err error) {
	log.Infof("ecc sign start")
	priv, ok := (*privateKey).(*ecdsa.PrivateKey)
	if !ok {
		return nil, response.ErrEccSignUnSupport
	}
	out, err = ecdsa.SignASN1(config.Rand, priv, ciphertext)
	if err != nil {
		log.ErrorContextf(ctx, "ecc sign failed:%+v", err)
		return
	}
	log.Infof("ecc sign success")
	return
}

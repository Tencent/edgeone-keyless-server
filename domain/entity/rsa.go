package entity

/*
#cgo LDFLAGS: /usr/lib64/libcrypto.a /usr/lib64/libz.a -ldl

#include <openssl/bn.h>

BIGNUM* mod_exp(const char* base, const char* exp, const char* mod) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *res = BN_new();

	BN_hex2bn(&a, base);
	BN_hex2bn(&b, exp);
	BN_hex2bn(&m, mod);

	BN_mod_exp(res, a, b, m, ctx);

	BN_free(a);
	BN_free(b);
	BN_free(m);
	BN_CTX_free(ctx);

	return res;
}

void free_bn(BIGNUM* bn) {
	BN_free(bn);
}
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"math/big"
	"unsafe"

	response "edgeone-keyless-server/infrastructure/constant"

	"trpc.group/trpc-go/trpc-go/log"
)

const (
	RSA_PKCS1_PADDING      = 1
	RSA_SSLV23_PADDING     = 2
	RSA_NO_PADDING         = 3
	RSA_PKCS1_OAEP_PADDING = 4
	RSA_X931_PADDING       = 5
	RSA_PKCS1_PSS_PADDING  = 6
)

// RsaKeyAgreement struct represents the RSA key agreement parameters.
type RsaKeyAgreement struct {
	Version uint16
	SigType crypto.Hash
}

// decryptNoPadding decrypts the ciphertext without padding.
func decryptNoPadding(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	ct := new(big.Int).SetBytes(ciphertext)
	plaintext := new(big.Int).Exp(ct, priv.D, priv.PublicKey.N)
	plaintextBytes := plaintext.Bytes()

	// If the length of the decrypted plaintext bytes is less than the byte length of the modulus,
	// add leading zero bytes.
	if len(plaintextBytes) < len(priv.PublicKey.N.Bytes()) {
		padding := make([]byte, len(priv.PublicKey.N.Bytes())-len(plaintextBytes))
		plaintextBytes = append(padding, plaintextBytes...)
	}

	return plaintextBytes
}

// Decrypt implements the decryption method for RSA key agreement.
func (r RsaKeyAgreement) Decrypt(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, padding int,
) ([]byte, error) {
	log.InfoContextf(ctx, "rsa Decrypt")
	priv, ok := (*privateKey).(*rsa.PrivateKey)
	if !ok {
		return nil, response.ErrRsaDecrypterNotImpl
	}
	log.InfoContextf(ctx, "ciphertext len:%d", len(ciphertext))
	// Perform constant time RSA PKCS#1 v1.5 decryption
	var preMasterSecret []byte
	var err error
	switch padding {
	case RSA_NO_PADDING:
		preMasterSecret = decryptNoPadding(ciphertext, priv)
	case RSA_PKCS1_PADDING:
		preMasterSecret, err = priv.Decrypt(config.Rand, ciphertext, nil)
		if err != nil {
			log.ErrorContextf(ctx, "decryption with RSA_PKCS1_PADDING failed: %v", err)
			return nil, response.ErrRsaDecrypterFail
		}
	case RSA_PKCS1_OAEP_PADDING:
		preMasterSecret, err = priv.Decrypt(config.Rand, ciphertext, &rsa.OAEPOptions{
			Hash:  r.SigType,
			Label: []byte(""),
		})
		if err != nil {
			log.ErrorContextf(ctx, "decryption with RSA_PKCS1_OAEP_PADDING failed: %v", err)
			return nil, response.ErrRsaDecrypterFail
		}
	default:
		log.ErrorContextf(ctx, "unknown padding type:%d", padding)
		return nil, response.ErrRsaDecrypterFailUnkownPadding
	}

	log.InfoContextf(ctx, "preMasterSecret :%x, len:%d", string(preMasterSecret), len(preMasterSecret))
	log.InfoContextf(ctx, "rsa Decrypt success")
	return preMasterSecret, nil
}

// privateEncrypt performs RSA private key encryption.
func privateEncrypt(plaintext []byte, privateKey *rsa.PrivateKey, padding int) ([]byte, error) {
	k := (privateKey.N.BitLen() + 7) / 8
	if len(plaintext) > k {
		return nil, response.ErrRsaPKWrongType
	}

	// Pre-allocate em space according to padding type
	var em []byte
	switch padding {
	case RSA_NO_PADDING:
		em = make([]byte, k)
		copy(em[k-len(plaintext):], plaintext)
	case RSA_PKCS1_PADDING:
		em = make([]byte, k)
		copy(em[11:], plaintext) // Start copying directly from index 11
		em[0] = 0x00
		em[1] = 0x01
		for i := 2; i < 11; i++ {
			em[i] = 0xFF
		}
	default:
		return nil, response.ErrRsaPKWrongType
	}

	m := new(big.Int).SetBytes(em)
	// Use openssl
	encrypted, err := opensslExp(m, privateKey.D, privateKey.N)
	if err != nil {
		log.Errorf("rsa private encrypt failed: %v", err)
		return nil, response.ErrRsaEncrypterFail
	}
	// If the encrypted data is less than k, pad it to k size
	if len(encrypted) < k {
		paddingBytes := make([]byte, k-len(encrypted))
		copy(encrypted, paddingBytes)
	}

	return encrypted, nil
}


func bigExp(x, y, n *big.Int) []byte {
	c := new(big.Int).Exp(x, y, n)
	return c.Bytes()
}


func opensslExp(x, y, n *big.Int) ([]byte, error) {
	baseStr := C.CString(x.Text(16))
	expStr := C.CString(y.Text(16))
	modStr := C.CString(n.Text(16))
	defer C.free(unsafe.Pointer(baseStr))
	defer C.free(unsafe.Pointer(expStr))
	defer C.free(unsafe.Pointer(modStr))

	result := C.mod_exp(baseStr, expStr, modStr)
	defer C.free_bn(result)
	hexResult := C.BN_bn2hex(result)
	defer C.free(unsafe.Pointer(hexResult))
	resultHex := C.GoString(hexResult)
	resultBytes, err := hex.DecodeString(resultHex)
	if err != nil {
		return nil, fmt.Errorf("Error decoding hex string:" + err.Error())
	}
	return resultBytes, nil
}

// Encrypt implements repository.KeyAgreement.
func (r RsaKeyAgreement) Encrypt(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, padding int,
) ([]byte, error) {
	log.InfoContextf(ctx, "rsa Encrypt")
	pk, ok := (*privateKey).(*rsa.PrivateKey)
	if !ok {
		log.ErrorContextf(ctx, "private key type wrong")
		return nil, response.ErrRsaPKWrongType
	}

	switch padding {
	case RSA_NO_PADDING, RSA_PKCS1_PADDING:
		return privateEncrypt(ciphertext, pk, padding)
	case RSA_PKCS1_OAEP_PADDING:
		return rsa.EncryptOAEP(r.SigType.New(), config.Rand, &(pk.PublicKey), ciphertext, nil)
	default:
		log.ErrorContextf(ctx, "unsupport padding :%d", padding)
		return nil, response.ErrRsaPKWrongType
	}
}

// Sign implements repository.KeyAgreement.
func (r RsaKeyAgreement) Sign(ctx context.Context, ciphertext []byte, config *tls.Config,
	privateKey *crypto.PrivateKey, pss bool,
) (out []byte, err error) {
	log.InfoContextf(ctx, "rsa Sign")
	pk, ok := (*privateKey).(*rsa.PrivateKey)
	if !ok {
		log.ErrorContextf(ctx, "private key type wrong")
		return nil, response.ErrRsaPKWrongType
	}
	if config == nil {
		log.ErrorContextf(ctx, "rand is nil")
		return nil, response.ErrRsaPKWrongType
	}
	log.InfoContextf(ctx, "msg len:%d, r.SigType :%d", len(ciphertext), r.SigType)
	if pss {
		log.InfoContextf(ctx, "rsa sign with pss")
		sigType := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: r.SigType}
		// MD5SHA1 is not supported as it has been phased out due to security issues
		if r.SigType == crypto.Hash(0) {
			log.ErrorContextf(ctx, "rsa sign with pss but sigType is MD5SHA1")
			return nil, response.ErrNotSupprotSignTypeMD5SHA1
		}
		out, err = pk.Sign(config.Rand, ciphertext, sigType)
	} else {
		out, err = pk.Sign(config.Rand, ciphertext, r.SigType)
	}

	if err != nil {
		log.ErrorContextf(ctx, "rsa sign failed:%+v", err)
		return nil, response.ErrRsaSignFail
	}
	log.InfoContextf(ctx, "rsa sign success")
	return
}

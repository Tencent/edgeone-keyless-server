package entity

import (
	"crypto"
	"crypto/cipher"
	"crypto/x509"

	"edgeone-keyless-server/domain/repository"
)

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	Ka     func(version uint16, sigType crypto.Hash) repository.KeyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) interface{}
	mac    func(version uint16, macKey []byte) macFunction
	aead   func(key, fixedNonce []byte) cipher.AEAD
}

var AttributeTypeNames = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
	"2.5.4.5":  "SERIALNUMBER",
	"2.5.4.7":  "L",
	"2.5.4.8":  "ST",
	"2.5.4.9":  "STREET",
	"2.5.4.17": "POSTALCODE",
}

const (
	SUITE_TLS_BASE = iota + -1
	RSA_SIGN       // RSA signature
	RSA_DECRYPT    // RSA decrypt
	RSA_ENCRYPT    // RSA encrypt
	ECC_SIGN       // ECC signature
	SUITE_TLS_TOPPER
)

const (
	NID_md5      = 4
	NID_sha1     = 64
	NID_md5_sha1 = 114
	NID_sha224   = 675
	NID_sha256   = 672
	NID_sha384   = 673
	NID_sha512   = 674
)

type KeyAgreementFactory struct {
	id uint16
	Ka func(version uint16, sigType crypto.Hash) repository.KeyAgreement
}

var KeyAgreementMap = map[uint16]*KeyAgreementFactory{
	RSA_SIGN: {
		RSA_SIGN, rsaKA,
	},
	RSA_DECRYPT: {
		RSA_DECRYPT, rsaKA,
	},
	RSA_ENCRYPT: {
		RSA_ENCRYPT, rsaKA,
	},
	ECC_SIGN: {
		ECC_SIGN, ecdheECDSAKA,
	},
}

var NidToHash = map[int]crypto.Hash{
	NID_md5:      crypto.MD5,
	NID_sha1:     crypto.SHA1,
	NID_sha224:   crypto.SHA224,
	NID_sha256:   crypto.SHA256,
	NID_sha384:   crypto.SHA384,
	NID_sha512:   crypto.SHA512,
	NID_md5_sha1: crypto.Hash(0),
}

var SSLAlgoMetricMap map[int32]string

const (
	RSA_SIGN_RECORD    = "RSA_SIGN"    // RSA签名
	RSA_DECRYPT_RECORD = "RSA_DECRYPT" // RSA解密
	RSA_ENCRYPT_RECORD = "RSA_ENCRYPT" // RSA加密
	ECC_SIGN_RECORD    = "ECC_SIGN"    // ECC签名
	ECC_DECRYPT_RECORD = "ECC_DECRYPT" // ECC解密
	ECC_ENCRYPT_RECORD = "ECC_ENCRYPT" // ECC加密
	CERT_LOAD_RECORD   = "CERT_LOAD"   // 加载证书
)

func init() {
	SSLAlgoMetricMap = make(map[int32]string)
	SSLAlgoMetricMap[RSA_SIGN] = RSA_SIGN_RECORD
	SSLAlgoMetricMap[RSA_DECRYPT] = RSA_DECRYPT_RECORD
	SSLAlgoMetricMap[RSA_ENCRYPT] = RSA_ENCRYPT_RECORD
	SSLAlgoMetricMap[ECC_SIGN] = ECC_SIGN_RECORD
}

const (
	PK_SUFFIX       = ".key" // 私钥后缀
	PUB_SUFFIX      = ".crt" // 公钥后缀
	CERT_PEM_SUFFIX = ".pem" // 证书后缀
)

const (
	SN_2_STRING_HEX = 16
)

// rsaKA creates a new RSA Key Agreement instance with the specified version and signature type.
func rsaKA(version uint16, sigType crypto.Hash) repository.KeyAgreement {
	return RsaKeyAgreement{
		// Hash: macSHA1,
		SigType: sigType,
		Version: version,
	}
}

// ecdheECDSAKA creates a new ECDHE-ECDSA Key Agreement instance with the specified version and signature type.
func ecdheECDSAKA(version uint16, sigType crypto.Hash) repository.KeyAgreement {
	return EccKeyAgreement{
		// sigType: signatureECDSA,
		// Hash: macSHA1,
		// SigType: crypto.MD5SHA1,
		SigType: sigType,
		Version: version,
	}
}

// IsRSAPSS checks if the given x509 SignatureAlgorithm is an RSA-PSS algorithm.
func IsRSAPSS(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

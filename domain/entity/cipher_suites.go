package entity

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"hash"

	"edgeone-keyless-server/domain/repository"
	"edgeone-keyless-server/infrastructure/constant"
)

type macFunction interface {
	Size() int
	MAC(digestBuf, seq, header, data []byte) []byte
}

func (s ssl30MAC) Size() int {
	return s.h.Size()
}

func (s tls10MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(header)
	s.h.Write(data)
	return s.h.Sum(digestBuf[:0])
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
	RSA_SIGN    = iota + 0 // RSA签名
	RSA_DECRYPT            // RSA解密
	RSA_ENCRYPT            // RSA加密
	ECC_SIGN               // ECC签名
	ECC_DECRYPT            // ECC解密
	ECC_ENCRYPT            // ECC加密
	// CERT_LOAD		   // 加载证书
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
	SSLAlgoMetricMap[ECC_DECRYPT] = ECC_DECRYPT_RECORD
	SSLAlgoMetricMap[ECC_ENCRYPT] = ECC_ENCRYPT_RECORD
}

const (
	PK_SUFFIX       = ".key" // 私钥后缀
	PUB_SUFFIX      = ".crt" // 公钥后缀
	CERT_PEM_SUFFIX = ".pem" // 证书后缀
)

const (
	SN_2_STRING_HEX = 16
)

const (
	// suiteECDH indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECDSA indicates that the cipher suite involves an ECDSA
	// signature and therefore may only be selected when the server's
	// certificate is ECDSA. If this is not set then the cipher suite is
	// RSA based.
	suiteECDSA
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384
	// suiteDefaultOff indicates that this cipher suite is not included by
	// default.
	suiteDefaultOff
)

const (
	TLS_RSA_WITH_RC4_128_SHA                uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA            uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            uint16 = 0x0035
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA          uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      uint16 = 0xc014
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See
	// https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00.
	TLS_FALLBACK_SCSV uint16 = 0x5600
)

type fixedNonceAEAD struct {
	// sealNonce and openNonce are buffers where the larger nonce will be
	// constructed. Since a seal and open operation may be running
	// concurrently, there is a separate buffer for each.
	sealNonce, openNonce []byte
	aead                 cipher.AEAD
}

func (f *fixedNonceAEAD) NonceSize() int { return 8 }
func (f *fixedNonceAEAD) Overhead() int  { return f.aead.Overhead() }

func (f *fixedNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.sealNonce[len(f.sealNonce)-8:], nonce)
	return f.aead.Seal(out, f.sealNonce, plaintext, additionalData)
}

func (f *fixedNonceAEAD) Open(out, nonce, plaintext, additionalData []byte) ([]byte, error) {
	copy(f.openNonce[len(f.openNonce)-8:], nonce)
	return f.aead.Open(out, f.openNonce, plaintext, additionalData)
}

func aeadAESGCM(key, fixedNonce []byte) cipher.AEAD {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	nonce1, nonce2 := make([]byte, 12), make([]byte, 12)
	copy(nonce1, fixedNonce)
	copy(nonce2, fixedNonce)

	return &fixedNonceAEAD{nonce1, nonce2, aead}
}

var CipherSuites = map[uint16]*cipherSuite{
	// Ciphersuite order is chosen so that ECDHE comes before plain RSA
	// and RC4 comes before AES (because of the Lucky13 attack).
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE |
		suiteTLS12, nil, nil, aeadAESGCM},

	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE |
		suiteECDSA | suiteTLS12, nil, nil, aeadAESGCM},

	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE |
		suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE |
		suiteECDSA | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},

	TLS_ECDHE_RSA_WITH_RC4_128_SHA: {TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE |
		suiteDefaultOff, cipherRC4, macSHA1, nil},

	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: {TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE |
		suiteECDSA | suiteDefaultOff, cipherRC4, macSHA1, nil},

	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: {
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE,
		cipherAES, macSHA1, nil,
	},

	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE |
		suiteECDSA, cipherAES, macSHA1, nil},

	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: {
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE,
		cipherAES, macSHA1, nil,
	},

	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: {TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE |
		suiteECDSA, cipherAES, macSHA1, nil},

	TLS_RSA_WITH_AES_128_GCM_SHA256: {
		TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, nil, nil,
		aeadAESGCM,
	},

	TLS_RSA_WITH_AES_256_GCM_SHA384: {
		TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384,
		nil, nil, aeadAESGCM,
	},

	TLS_RSA_WITH_RC4_128_SHA: {
		TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, suiteDefaultOff, cipherRC4,
		macSHA1, nil,
	},

	TLS_RSA_WITH_AES_128_CBC_SHA: {
		TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1,
		nil,
	},

	TLS_RSA_WITH_AES_256_CBC_SHA: {
		TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1,
		nil,
	},

	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: {
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE,
		cipher3DES, macSHA1, nil,
	},

	TLS_RSA_WITH_3DES_EDE_CBC_SHA: {
		TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1,
		nil,
	},
}

func cipherRC4(key, iv []byte, isRead bool) interface{} {
	cipher, _ := rc4.NewCipher(key)
	return cipher
}

func cipher3DES(key, iv []byte, isRead bool) interface{} {
	block, _ := des.NewTripleDESCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

func cipherAES(key, iv []byte, isRead bool) interface{} {
	block, _ := aes.NewCipher(key)
	if isRead {
		return cipher.NewCBCDecrypter(block, iv)
	}
	return cipher.NewCBCEncrypter(block, iv)
}

type tls10MAC struct {
	h hash.Hash
}

type ssl30MAC struct {
	h   hash.Hash
	key []byte
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

var ssl30Pad1 = [48]byte{
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
}

var ssl30Pad2 = [48]byte{
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
}

func (s ssl30MAC) MAC(digestBuf, seq, header, data []byte) []byte {
	padLength := constant.PAD_LEN_MD5
	if s.h.Size() == constant.SHA1_LEN {
		padLength = constant.PAD_LEN_SHA1
	}

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad1[:padLength])
	s.h.Write(seq)
	s.h.Write(header[:1])
	s.h.Write(header[3:5])
	s.h.Write(data)
	digestBuf = s.h.Sum(digestBuf[:0])

	s.h.Reset()
	s.h.Write(s.key)
	s.h.Write(ssl30Pad2[:padLength])
	s.h.Write(digestBuf)
	return s.h.Sum(digestBuf[:0])
}

// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
	if version == tls.VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha1.New, key)}
}

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

// ecdheRSAKA creates a new ECDHE-RSA Key Agreement instance with the specified version and signature type.
func ecdheRSAKA(version uint16, sigType crypto.Hash) repository.KeyAgreement {
	return EccKeyAgreement{
		// sigType: signatureRSA,
		// Hash: macSHA1,
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

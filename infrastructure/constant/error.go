package constant

import (
	"trpc.group/trpc-go/trpc-go/errs"
)

var (
	// tls: invalid ClientKeyExchange message
	ErrClientKeyExchange = errs.New(KS_RSA_DECRYPT_FAIL, "tls: invalid ClientKeyExchange message")
	// tls: invalid ServerKeyExchange message
	ErrServerKeyExchange = errs.New(KS_CRYPT_FAIL, "tls: invalid ServerKeyExchange message")
	// tls: certificate private key does not implement crypto.Decrypter
	ErrRsaDecrypterNotImpl = errs.New(KS_RSA_DECRYPT_FAIL, "tls: certificate private key does not implement"+
		"crypto.Decrypter")
	// tls: certificate private key decrypt failed
	ErrRsaDecrypterFail = errs.New(KS_RSA_DECRYPT_FAIL, "tls: certificate private key decrypt failed")
	// tls: certificate private key encrypt failed
	ErrRsaEncrypterFail = errs.New(KS_RSA_DECRYPT_FAIL, "tls: certificate private key encrypt failed")
	// tls: unknown padding type
	ErrRsaDecrypterFailUnkownPadding = errs.New(KS_RSA_DECRYPT_FAIL, "tls: unknown padding type")
	// tls: certificate private key does not implement crypto.Decrypter
	ErrNotSupprotCipher = errs.New(KS_KEY_NOT_FOUND, "tls: certificate private key does not implement"+
		"crypto.Decrypter")
	// crypto/tls: found unknown private key type in PKCS#8 wrapping
	ErrUnknownPK = errs.New(KS_CRYPT_FAIL, "crypto/tls: found unknown private key type in PKCS#8"+
		"wrapping")
	// crypto/tls: failed to parse private key
	ErrWrongPK = errs.New(KS_CRYPT_FAIL, "crypto/tls: failed to parse private key")
	// crypto/tls: failed to parse certificate
	ErrWrongPublic = errs.New(KS_CRYPT_FAIL, "crypto/tls: failed to parse certificate")
	// config: failed to parse config
	ErrParseConfig = errs.New(KS_ERROR, "config: failed to parse config")
	// tls: certificate private key does not exist
	ErrPKNotFound = errs.New(KS_KEY_NOT_FOUND, "tls: certificate private key does not exist")
	// RLock: get lock failed
	ErrRLockFailed = errs.New(KS_ERROR, "RLock: get lock failed")
	// tls: certificate private key does not implement crypto.Signer
	ErrNotSupprotSignType = errs.New(KS_RSA_SIGN_FAIL, "tls: certificate private key does not implement"+
		"crypto.Signer")
	// tls: certificate private key does not support md5sha1
	ErrNotSupprotSignTypeMD5SHA1 = errs.New(KS_RSA_SIGN_FAIL, "tls: certificate private key does not support md5sha1")
	// tls: certificate private key does not implement crypto.Signer
	ErrRsaSignFail = errs.New(KS_RSA_SIGN_FAIL, "tls: certificate private key does not implement"+
		"crypto.Signer")
	// tls: certificate private key type is wrong
	ErrRsaPKWrongType = errs.New(KS_RSA_SIGN_FAIL, "tls: certificate private key type is wrong")
	// tls: certificate private key type is wrong
	ErrRsaEncryptFail = errs.New(KS_RSA_SIGN_FAIL, "tls: certificate private key type is wrong")
	// tls: certificate private key does not implement crypto.Signer
	ErrEccSignUnSupport = errs.New(KS_ECC_SIGN_FAIL, "tls: certificate private key does not implement"+
		"crypto.Signer")
	// ECDHE ECDSA requires an ECDSA server key
	ErrLackOfECDHE = errs.New(KS_ERROR, "ECDHE ECDSA requires an ECDSA server key")
	// msg:Wrong request type
	ErrWrongReqType = errs.New(KS_ERROR, "msg:Wrong request type")
)

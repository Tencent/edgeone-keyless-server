package constant

const (
	KS_OK               = 0   // OK
	KS_INVALID_IP       = -1  // Invalid IP
	KS_KEY_NOT_FOUND    = -2  // Key not found
	KS_RSA_INFO_ERR     = -3  // RSA info error
	KS_CRYPT_FAIL       = -4  // RSA encrypt/decrypt fail
	KS_CRYPT_TOO_LONG   = -5  // RSA encrypt/decrypt fail
	KS_AES_ENCRYPT_FAIL = -6  // AES encrypt fail
	KS_AES_DECRYPT_FAIL = -7  // AES decrypt fail
	KS_RSA_SIGN_FAIL    = -8  // RSA sign fail
	KS_RSA_DECRYPT_FAIL = -9  // RSA decrypt fail
	KS_ERROR            = -10 // Error
	KS_RSA_ENCRYPT_FAIL = -11 // RSA encrypt fail
	KS_ECC_SIGN_FAIL    = -12 // ECC sign fail
	KS_ECC_DECRYPT_FAIL = -13 // ECC decrypt fail
)

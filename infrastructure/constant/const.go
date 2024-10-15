package constant

const (
	HTTP_SERVER  = "trpc.app.server.keylessHTTP"        // keyless http server
	HTTPS_SERVER = "trpc.app.server.keylessHTTPSMutual" // keyless https server
)

const (
	MSG_UUID_NAME = "SeqId" // uuid
) // uuid

const (
	PAD_LEN_MD5  = 48 // default pad length
	PAD_LEN_SHA1 = 40 // default pad length
	SHA1_LEN     = 20 // sha1 length
)

const (
	PRIVAETE_KEY     = "PRIVATE KEY"     // ecc
	PRIVAETE_KEY_ECC = "EC PRIVATE KEY"  // ecc
	PRIVAETE_KEY_RSA = "RSA PRIVATE KEY" // rsa

)

const (
	TIME_FORMAT   = "2006-01-02 15:04:05"
	TIME_LOCATION = "Asia/Shanghai"
)

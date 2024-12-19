package entity

const (
	KEYLESS_CONFIG_PATH = "/config/keyless.yaml"
)

// Conf holds the configuration settings for the application.
type Conf struct {
	Config *KeylessConfig
}
// KeylessConfig holds the configuration settings for the keyless server.
type KeylessConfig struct {
	// Path to the private key
	PrivateKeyPath string `json:"private_key_path" yaml:"private_key_path" validate:"required"`
	// Path to the mutual TLS certificates for two-way authentication with workers
	MutualCertsPath string `json:"mutual_certs_path" yaml:"mutual_certs_path" validate:"required"`
	// Whether to prefer server cipher suites
	PreferServerCipherSuites bool `json:"prefer_server_cipher_suites" yaml:"prefer_server_cipher_suites" validate:"required"`
	Version string `json:"version" yaml:"version" validate:"required"`
	// Path to the log file
	LogPath string `json:"log_path" yaml:"log_path" validate:"required"`
}

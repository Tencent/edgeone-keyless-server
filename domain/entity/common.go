package entity

import (
	"crypto"
	"crypto/x509"
)

// CertificateInfo holds the certificate information.
type CertificateInfo struct {
	// Certificate name
	CertName string
	// Public key text information
	RawPublicKey []byte
	// Private key text information
	RawPrivateKey []byte
	// Parsed public key
	PublicKey *x509.Certificate
	// Parsed private key
	PrivateKey crypto.PrivateKey
}

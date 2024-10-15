package repository

import "github.com/johnnyqchen/edgeone-keyless-server/infrastructure/protocol/keyless"

// KeylessService is the interface for keyless service.
type KeylessService interface {
	keyless.KeylessServiceService
}

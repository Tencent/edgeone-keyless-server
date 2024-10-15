package repository

import "git.woa.com/johnnyqchen/mutual_https/infrastructure/protocol/keyless"

// KeylessService is the interface for keyless service.
type KeylessService interface {
	keyless.KeylessServiceService
}

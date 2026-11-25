package store

import "context"

// UIAuthRepository stores the single local UI account credential.
type UIAuthRepository interface {
	Get(ctx context.Context) (username, passwordHash string, enabled bool, err error)
	Set(ctx context.Context, username, passwordHash string) error
	Disable(ctx context.Context) error
}

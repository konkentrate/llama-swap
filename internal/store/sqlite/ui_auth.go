package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mostlygeek/llama-swap/internal/store"
)

type uiAuthRepository struct {
	db         *sql.DB
	persistent bool
}

var _ store.UIAuthRepository = (*uiAuthRepository)(nil)

func (r *uiAuthRepository) Get(ctx context.Context) (string, string, bool, error) {
	var username, hash string
	err := r.db.QueryRowContext(ctx, `SELECT username, password_hash FROM ui_auth WHERE id = 1`).Scan(&username, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("read UI auth: %w", err)
	}
	return username, hash, true, nil
}

func (r *uiAuthRepository) Set(ctx context.Context, username, hash string) error {
	if !r.persistent {
		return errors.New("UI auth setup requires a persistent store")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO ui_auth (id, username, password_hash) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash`, username, hash)
	if err != nil {
		return fmt.Errorf("save UI auth: %w", err)
	}
	return nil
}

func (r *uiAuthRepository) Disable(ctx context.Context) error {
	if !r.persistent {
		return errors.New("UI auth requires a persistent store")
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM ui_auth WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("disable UI auth: %w", err)
	}
	return nil
}

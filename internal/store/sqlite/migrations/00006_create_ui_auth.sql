-- +goose Up
CREATE TABLE ui_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

-- +goose Down
DROP TABLE ui_auth;

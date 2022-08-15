-- +goose Up

CREATE SCHEMA [authz];

-- +goose Down

DROP SCHEMA [authz];

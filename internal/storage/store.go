package storage

import "context"

type Store interface {
	Ping(ctx context.Context) error
	Get(ctx context.Context, key string) (string, bool, error)
	Take(ctx context.Context, key string) (string, bool, error)
	SetEx(ctx context.Context, key, value string, ttlSeconds int) error
}

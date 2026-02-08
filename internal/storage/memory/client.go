package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/allegro/bigcache/v3"
)

type Client struct {
	cache *bigcache.BigCache
}

type entry struct {
	Value     string `json:"value"`
	ExpiresAt int64  `json:"expires_at"`
}

func New() (*Client, error) {
	cache, err := bigcache.New(context.Background(), bigcache.Config{
		Shards:           1024,
		LifeWindow:       24 * time.Hour,
		CleanWindow:      5 * time.Minute,
		MaxEntrySize:     4096,
		HardMaxCacheSize: 64,
		Verbose:          false,
	})
	if err != nil {
		return nil, err
	}
	return &Client{cache: cache}, nil
}

func (c *Client) Ping(_ context.Context) error {
	return nil
}

func (c *Client) Get(_ context.Context, key string) (string, bool, error) {
	raw, err := c.cache.Get(key)
	if errors.Is(err, bigcache.ErrEntryNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", false, err
	}
	if time.Now().Unix() >= e.ExpiresAt {
		_ = c.cache.Delete(key)
		return "", false, nil
	}
	return e.Value, true, nil
}

func (c *Client) Take(ctx context.Context, key string) (string, bool, error) {
	value, ok, err := c.Get(ctx, key)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	if err := c.cache.Delete(key); err != nil && !errors.Is(err, bigcache.ErrEntryNotFound) {
		return "", false, err
	}
	return value, true, nil
}

func (c *Client) SetEx(_ context.Context, key, value string, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		return fmt.Errorf("ttl must be positive: %d", ttlSeconds)
	}
	payload, err := json.Marshal(entry{
		Value:     value,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix(),
	})
	if err != nil {
		return err
	}
	return c.cache.Set(key, payload)
}

package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

var ErrNil = goredis.Nil

type Client struct {
	client *goredis.Client
}

func New(redisURL string) (*Client, error) {
	opt, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := goredis.NewClient(opt)
	return &Client{client: client}, nil
}

func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *Client) Get(ctx context.Context, key string) (string, bool, error) {
	value, err := c.client.Get(ctx, key).Result()
	if err == goredis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (c *Client) SetEx(ctx context.Context, key, value string, ttlSeconds int) error {
	return c.client.SetEx(ctx, key, value, time.Duration(ttlSeconds)*time.Second).Err()
}

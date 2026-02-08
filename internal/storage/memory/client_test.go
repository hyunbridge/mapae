package memory

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSetExGetTakeFlow(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if err := c.SetEx(ctx, "k", "v", 10); err != nil {
		t.Fatalf("SetEx() error = %v", err)
	}

	got, ok, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || got != "v" {
		t.Fatalf("Get() = (%q,%t), want (v,true)", got, ok)
	}

	taken, ok, err := c.Take(ctx, "k")
	if err != nil {
		t.Fatalf("Take() error = %v", err)
	}
	if !ok || taken != "v" {
		t.Fatalf("Take() = (%q,%t), want (v,true)", taken, ok)
	}

	_, ok, err = c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get() after take error = %v", err)
	}
	if ok {
		t.Fatalf("key should be deleted after Take")
	}
}

func TestSetExRejectsNonPositiveTTL(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := c.SetEx(context.Background(), "k", "v", 0); err == nil {
		t.Fatalf("expected error for non-positive ttl")
	}
}

func TestGetExpiredEntry(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	payload, err := json.Marshal(entry{Value: "v", ExpiresAt: time.Now().Add(-time.Second).Unix()})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := c.cache.Set("expired", payload); err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	_, ok, err := c.Get(context.Background(), "expired")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Fatalf("expired key should be treated as not found")
	}
}

func TestGetInvalidPayloadReturnsError(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := c.cache.Set("broken", []byte("not-json")); err != nil {
		t.Fatalf("cache.Set() error = %v", err)
	}

	if _, _, err := c.Get(context.Background(), "broken"); err == nil {
		t.Fatalf("Get() should fail for invalid payload")
	}
}

package memory

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
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

func TestTakeIsAtomicUnderConcurrency(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx := context.Background()
	if err := c.SetEx(ctx, "nonce", "auth-id", 60); err != nil {
		t.Fatalf("SetEx() error = %v", err)
	}

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	var successCount int32

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, ok, err := c.Take(ctx, "nonce")
			if err != nil {
				t.Errorf("Take() error = %v", err)
				return
			}
			if ok {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&successCount); got != 1 {
		t.Fatalf("successful Take count = %d, want 1", got)
	}
}

package redis

import "testing"

func TestNewInvalidURL(t *testing.T) {
	if _, err := New("not-a-redis-url"); err == nil {
		t.Fatalf("New() should fail for invalid redis url")
	}
}

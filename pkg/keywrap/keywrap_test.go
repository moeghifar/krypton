package keywrap

import (
	"bytes"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

// RFC 3394 test vector: AES-128-KW (we test AES-256-KW with our key)
func TestKeyWrap_AES256KW(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("0123456789ABCDEF") // 16 bytes = 2 blocks

	wrapped, err := KeyWrap(key, plaintext, "AES-256-KW")
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(key, wrapped, "AES-256-KW")
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, plaintext) {
		t.Errorf("Round-trip failed: got %x, want %x", unwrapped, plaintext)
	}
}

func TestKeyWrap_AES256KW_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	plaintext := []byte("0123456789ABCDEF")

	wrapped, _ := KeyWrap(key, plaintext, "AES-256-KW")
	_, err := KeyUnwrap(wrongKey, wrapped, "AES-256-KW")
	if err == nil {
		t.Error("KeyUnwrap should fail with wrong key")
	}
}

func TestKeyWrap_AES256KW_InvalidInput(t *testing.T) {
	key := make([]byte, 32)

	// Empty input
	_, err := KeyWrap(key, []byte{}, "AES-256-KW")
	if err == nil {
		t.Error("KeyWrap should fail with empty input")
	}

	// Non-multiple of 8
	_, err = KeyWrap(key, []byte("1234567"), "AES-256-KW")
	if err == nil {
		t.Error("KeyWrap should fail with non-multiple-of-8 input")
	}
}

func TestKeyWrap_AES256KWP(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	// Test with non-multiple-of-8 input (padding needed)
	plaintext := []byte("Hello!") // 6 bytes

	wrapped, err := KeyWrap(key, plaintext, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(key, wrapped, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, plaintext) {
		t.Errorf("KWP round-trip failed: got %q, want %q", unwrapped, plaintext)
	}
}

func TestKeyWrap_AES256KWP_MultipleOf8(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("01234567") // exactly 8 bytes

	wrapped, err := KeyWrap(key, plaintext, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(key, wrapped, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, plaintext) {
		t.Error("KWP round-trip failed for 8-byte input")
	}
}

func TestKeyWrap_AES256KWP_SingleByte(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("A") // 1 byte

	wrapped, err := KeyWrap(key, plaintext, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyWrap failed: %v", err)
	}

	unwrapped, err := KeyUnwrap(key, wrapped, "AES-256-KWP")
	if err != nil {
		t.Fatalf("KeyUnwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, plaintext) {
		t.Errorf("KWP round-trip failed for 1-byte input: got %q", unwrapped)
	}
}

func TestKeyWrap_InvalidKeySize(t *testing.T) {
	_, err := KeyWrap(make([]byte, 16), []byte("01234567"), "AES-256-KW")
	if err == nil {
		t.Error("KeyWrap should fail with 16-byte key")
	}
}

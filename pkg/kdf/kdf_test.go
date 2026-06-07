package kdf

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestKDF_HKDF_SHA256(t *testing.T) {
	ikm := make([]byte, 32)
	rand.Read(ikm)
	salt := make([]byte, 32)
	rand.Read(salt)
	info := []byte("test-info")

	key, err := KDF(ikm, salt, info, 32, "HKDF-SHA256")
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}

	// Deterministic
	key2, _ := KDF(ikm, salt, info, 32, "HKDF-SHA256")
	if !bytes.Equal(key, key2) {
		t.Error("HKDF is not deterministic")
	}
}

func TestKDF_HKDF_SHA384(t *testing.T) {
	ikm := make([]byte, 48)
	rand.Read(ikm)
	salt := make([]byte, 48)
	rand.Read(salt)
	info := []byte("test")

	key, err := KDF(ikm, salt, info, 48, "HKDF-SHA384")
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}
	if len(key) != 48 {
		t.Errorf("key length: got %d, want 48", len(key))
	}
}

func TestKDF_HKDF_SHA512(t *testing.T) {
	ikm := make([]byte, 64)
	rand.Read(ikm)
	key, err := KDF(ikm, nil, nil, 64, "HKDF-SHA512")
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("key length: got %d, want 64", len(key))
	}
}

func TestKDF_HKDF_LengthBounds(t *testing.T) {
	ikm := make([]byte, 32)
	salt := make([]byte, 16)

	// Too short
	_, err := KDF(ikm, salt, nil, 15, "HKDF-SHA256")
	if err == nil {
		t.Error("KDF should fail with length < 16")
	}

	// Too long
	_, err = KDF(ikm, salt, nil, 513, "HKDF-SHA256")
	if err == nil {
		t.Error("KDF should fail with length > 512")
	}

	// Max valid
	key, err := KDF(ikm, salt, nil, 512, "HKDF-SHA256")
	if err != nil {
		t.Fatalf("KDF failed with length 512: %v", err)
	}
	if len(key) != 512 {
		t.Errorf("key length: got %d, want 512", len(key))
	}
}

func TestKDF_SP800_108_CTR(t *testing.T) {
	ikm := make([]byte, 32)
	salt := make([]byte, 16)
	info := []byte("sp800-info")

	key, err := KDF(ikm, salt, info, 32, "SP800-108-CTR")
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestKDF_ANSI_X963(t *testing.T) {
	ikm := make([]byte, 32)
	salt := make([]byte, 16)
	info := []byte("x963-info")

	key, err := KDF(ikm, salt, info, 32, "ANSI-X9.63")
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestKDFPassword_PBKDF2_SHA256(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	params := PasswordParams{
		Iterations: 600000,
		Length:     32,
	}

	key, err := KDFPassword("test-password", salt, params, "PBKDF2-SHA256")
	if err != nil {
		t.Fatalf("KDFPassword failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestKDFPassword_PBKDF2_IterationsTooLow(t *testing.T) {
	salt := make([]byte, 16)
	params := PasswordParams{Iterations: 1000, Length: 32}

	_, err := KDFPassword("test-password", salt, params, "PBKDF2-SHA256")
	if err == nil {
		t.Error("KDFPassword should fail with iterations < 600000")
	}
}

func TestKDFPassword_Argon2id(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	params := PasswordParams{
		MemoryKB:    65536,
		Iterations:  2,
		Parallelism: 1,
		Length:      32,
	}

	key, err := KDFPassword("test-password", salt, params, "Argon2id")
	if err != nil {
		t.Fatalf("KDFPassword failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestKDFPassword_Argon2id_MemoryTooLow(t *testing.T) {
	salt := make([]byte, 16)
	params := PasswordParams{MemoryKB: 1024, Iterations: 2, Parallelism: 1, Length: 32}

	_, err := KDFPassword("test-password", salt, params, "Argon2id")
	if err == nil {
		t.Error("KDFPassword should fail with memory < 32768 KB")
	}
}

func TestKDFPassword_Scrypt(t *testing.T) {
	salt := make([]byte, 16)
	rand.Read(salt)

	params := PasswordParams{
		N:       1 << 14, // 16384
		R:       8,
		P:       1,
		Length:  32,
	}

	key, err := KDFPassword("test-password", salt, params, "scrypt")
	if err != nil {
		t.Fatalf("KDFPassword failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
}

func TestKDFPassword_Bcrypt(t *testing.T) {
	params := PasswordParams{Cost: 10}

	hash, err := KDFPassword("test-password", nil, params, "bcrypt")
	if err != nil {
		t.Fatalf("KDFPassword failed: %v", err)
	}
	if len(hash) == 0 {
		t.Error("bcrypt hash should not be empty")
	}
}

func TestKDFPassword_Bcrypt_CostTooLow(t *testing.T) {
	params := PasswordParams{Cost: 4}

	_, err := KDFPassword("test-password", nil, params, "bcrypt")
	if err == nil {
		t.Error("KDFPassword should fail with bcrypt cost < 10")
	}
}

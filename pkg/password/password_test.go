package password

import (
	"strings"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestPasswordHash_Argon2id(t *testing.T) {
	params := PasswordParams{
		MemoryKB:    65536,
		Iterations:  2,
		Parallelism: 1,
		Length:      32,
	}

	hash, err := PasswordHash("test-password", algorithmArgon2id, params)
	if err != nil {
		t.Fatalf("PasswordHash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Argon2id hash should start with $argon2id$, got: %s", hash)
	}

	ok, err := PasswordVerify("test-password", hash)
	if err != nil {
		t.Fatalf("PasswordVerify failed: %v", err)
	}
	if !ok {
		t.Error("PasswordVerify returned false for correct password")
	}

	ok, err = PasswordVerify("wrong-password", hash)
	if err != nil {
		t.Fatalf("PasswordVerify failed: %v", err)
	}
	if ok {
		t.Error("PasswordVerify returned true for wrong password")
	}
}

func TestPasswordHash_Bcrypt(t *testing.T) {
	params := PasswordParams{Cost: 10}

	hash, err := PasswordHash("test-password", algorithmBcrypt, params)
	if err != nil {
		t.Fatalf("PasswordHash failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("bcrypt hash should start with $2, got: %s", hash)
	}

	ok, err := PasswordVerify("test-password", hash)
	if err != nil {
		t.Fatalf("PasswordVerify failed: %v", err)
	}
	if !ok {
		t.Error("PasswordVerify returned false for correct password")
	}

	ok, err = PasswordVerify("wrong-password", hash)
	if err != nil {
		t.Fatalf("PasswordVerify failed: %v", err)
	}
	if ok {
		t.Error("PasswordVerify returned true for wrong password")
	}
}

func TestPasswordHash_Bcrypt_CostTooLow(t *testing.T) {
	params := PasswordParams{Cost: 4}
	_, err := PasswordHash("test-password", algorithmBcrypt, params)
	if err == nil {
		t.Error("PasswordHash should fail with bcrypt cost < 10")
	}
}

func TestPasswordVerify_UnknownFormat(t *testing.T) {
	_, err := PasswordVerify("password", "unknown-hash-format")
	if err == nil {
		t.Error("PasswordVerify should fail for unknown hash format")
	}
}

func TestPasswordHash_Argon2id_DefaultParams(t *testing.T) {
	params := PasswordParams{} // Use defaults

	hash, err := PasswordHash("test-password", algorithmArgon2id, params)
	if err != nil {
		t.Fatalf("PasswordHash failed: %v", err)
	}

	ok, err := PasswordVerify("test-password", hash)
	if err != nil {
		t.Fatalf("PasswordVerify failed: %v", err)
	}
	if !ok {
		t.Error("PasswordVerify failed with default params")
	}
}

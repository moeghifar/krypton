package fpe

import (
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestFPEEncrypt_FF1_Numeric(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	tweak := []byte("test-tweak")
	plaintext := "1234567890"

	ciphertext, err := FPEEncrypt(key, plaintext, tweak, "numeric", "FF1")
	if err != nil {
		t.Fatalf("FPEEncrypt failed: %v", err)
	}
	if len(ciphertext) != len(plaintext) {
		t.Errorf("FPE output length: got %d, want %d", len(ciphertext), len(plaintext))
	}

	// All chars should be numeric
	for i := range ciphertext {
		if ciphertext[i] < '0' || ciphertext[i] > '9' {
			t.Errorf("FPE output contains non-numeric char: %c", ciphertext[i])
		}
	}

	// Different from plaintext (probabilistically)
	if ciphertext == plaintext {
		t.Log("Warning: FPE output equals plaintext (possible but unlikely)")
	}
}

func TestFPEDecrypt_FF1_Numeric(t *testing.T) {
	key := make([]byte, 32)
	tweak := []byte("test-tweak")
	plaintext := "12345678901234567890"

	ciphertext, err := FPEEncrypt(key, plaintext, tweak, "numeric", "FF1")
	if err != nil {
		t.Fatalf("FPEEncrypt failed: %v", err)
	}

	decrypted, err := FPEDecrypt(key, ciphertext, tweak, "numeric", "FF1")
	if err != nil {
		t.Fatalf("FPEDecrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestFPEDecrypt_FF1_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	tweak := []byte("test-tweak")
	plaintext := "123456789012345"

	ct, _ := FPEEncrypt(key, plaintext, tweak, "numeric", "FF1")
	decrypted, err := FPEDecrypt(wrongKey, ct, tweak, "numeric", "FF1")
	if err != nil {
		t.Fatalf("FPEDecrypt failed: %v", err)
	}
	if decrypted == plaintext {
		t.Error("Decryption with wrong key should not produce original plaintext")
	}
}

func TestFPEEncrypt_InvalidAlphabet(t *testing.T) {
	key := make([]byte, 32)
	_, err := FPEEncrypt(key, "test", []byte{}, "invalid-alphabet", "FF1")
	if err == nil {
		t.Error("FPEEncrypt should fail with invalid alphabet")
	}
}

func TestFPEEncrypt_InvalidChars(t *testing.T) {
	key := make([]byte, 32)
	// "abc" is not valid for numeric alphabet
	_, err := FPEEncrypt(key, "abc", []byte{}, "numeric", "FF1")
	if err == nil {
		t.Error("FPEEncrypt should fail with chars outside alphabet")
	}
}

func TestFPEEncrypt_CustomAlphabet(t *testing.T) {
	key := make([]byte, 32)
	tweak := []byte("tweak")
	plaintext := "FACE"

	ct, err := FPEEncrypt(key, plaintext, tweak, "custom:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "FF1")
	if err != nil {
		t.Fatalf("FPEEncrypt failed: %v", err)
	}

	pt, err := FPEDecrypt(key, ct, tweak, "custom:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "FF1")
	if err != nil {
		t.Fatalf("FPEDecrypt failed: %v", err)
	}
	if pt != plaintext {
		t.Errorf("Custom alphabet round-trip failed: got %q, want %q", pt, plaintext)
	}
}

func TestFPEEncrypt_InvalidKeySize(t *testing.T) {
	key := make([]byte, 24)
	_, err := FPEEncrypt(key, "12345", []byte{}, "numeric", "FF1")
	if err == nil {
		t.Error("FPEEncrypt should fail with non-32-byte key")
	}
}

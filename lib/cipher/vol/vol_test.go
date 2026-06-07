package vol

import (
	"bytes"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestEncryptDecryptVol_AES256XTS(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	tweak := make([]byte, 16)
	tweak[0] = 0x01
	data := make([]byte, 64) // must be multiple of 16
	for i := range data {
		data[i] = byte(i)
	}

	ct, err := EncryptVol(key, data, tweak, "AES-256-XTS")
	if err != nil {
		t.Fatalf("EncryptVol failed: %v", err)
	}
	if len(ct) != len(data) {
		t.Errorf("XTS output length: got %d, want %d", len(ct), len(data))
	}

	pt, err := DecryptVol(key, ct, tweak, "AES-256-XTS")
	if err != nil {
		t.Fatalf("DecryptVol failed: %v", err)
	}
	if !bytes.Equal(pt, data) {
		t.Error("XTS round-trip failed")
	}
}

func TestEncryptVol_InvalidKeySize(t *testing.T) {
	key := make([]byte, 32)
	_, err := EncryptVol(key, make([]byte, 32), make([]byte, 16), "AES-256-XTS")
	if err == nil {
		t.Error("EncryptVol should fail with 32-byte key")
	}
}

func TestEncryptVol_InvalidTweakSize(t *testing.T) {
	key := make([]byte, 64)
	_, err := EncryptVol(key, make([]byte, 32), make([]byte, 8), "AES-256-XTS")
	if err == nil {
		t.Error("EncryptVol should fail with non-16-byte tweak")
	}
}

func TestEncryptVol_InvalidDataLength(t *testing.T) {
	key := make([]byte, 64)
	_, err := EncryptVol(key, make([]byte, 17), make([]byte, 16), "AES-256-XTS")
	if err == nil {
		t.Error("EncryptVol should fail with non-multiple-of-16 data")
	}
}

func TestEncryptVol_EmptyData(t *testing.T) {
	key := make([]byte, 64)
	_, err := EncryptVol(key, []byte{}, make([]byte, 16), "AES-256-XTS")
	if err == nil {
		t.Error("EncryptVol should fail with empty data")
	}
}

func TestEncryptVol_WrongTweak(t *testing.T) {
	key := make([]byte, 64)
	data := make([]byte, 32)
	tweak1 := make([]byte, 16)
	tweak2 := make([]byte, 16)
	tweak2[0] = 0xFF

	ct, _ := EncryptVol(key, data, tweak1, "AES-256-XTS")
	pt, err := DecryptVol(key, ct, tweak2, "AES-256-XTS")
	if err != nil {
		t.Fatalf("DecryptVol failed: %v", err)
	}
	// Wrong tweak should produce garbage, not original data
	if bytes.Equal(pt, data) {
		t.Error("Decrypt with wrong tweak should not produce original data")
	}
}

func TestEncryptVol_DifferentSectors(t *testing.T) {
	key := make([]byte, 64)
	data := make([]byte, 32)
	for i := range data {
		data[i] = 0xAB
	}

	tweak1 := make([]byte, 16) // sector 0
	tweak2 := make([]byte, 16)
	tweak2[15] = 1 // sector 1

	ct1, _ := EncryptVol(key, data, tweak1, "AES-256-XTS")
	ct2, _ := EncryptVol(key, data, tweak2, "AES-256-XTS")

	// Same data, different sectors should produce different ciphertext
	if bytes.Equal(ct1, ct2) {
		t.Error("Same data in different sectors should produce different ciphertext")
	}
}

// Copyright 2026 M Ghiyast Farisi
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cipher

import (
	"bytes"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

func TestEncryptDecrypt_AES256GCM(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("Hello, World! This is a test of AES-256-GCM encryption.")
	context := "test-context"

	env, err := Encrypt(key, plaintext, context, AlgorithmAES256GCM)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, env, context, AlgorithmAES256GCM)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_AES256GCM_WrongContext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test data")

	env, err := Encrypt(key, plaintext, "correct-context", AlgorithmAES256GCM)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(key, env, "wrong-context", AlgorithmAES256GCM)
	if err == nil {
		t.Error("Decrypt should fail with wrong context")
	}
}

func TestEncryptDecrypt_AES256GCM_WrongKey(t *testing.T) {
	key := make([]byte, 32)
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	plaintext := []byte("test data")

	env, err := Encrypt(key, plaintext, "ctx", AlgorithmAES256GCM)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(wrongKey, env, "ctx", AlgorithmAES256GCM)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestEncryptDecrypt_ChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 10)
	}
	plaintext := []byte("Hello, World! This is a test of ChaCha20-Poly1305.")
	context := "chacha-context"

	env, err := Encrypt(key, plaintext, context, AlgorithmChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(key, env, context, AlgorithmChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_ChaCha20Poly1305_WrongContext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("test data")

	env, err := Encrypt(key, plaintext, "ctx1", AlgorithmChaCha20Poly1305)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(key, env, "ctx2", AlgorithmChaCha20Poly1305)
	if err == nil {
		t.Error("Decrypt should fail with wrong context")
	}
}

func TestEncryptDecryptDet_AES256SIV(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("deterministic encryption test")
	context := "siv-context"

	ct1, err := EncryptDet(key, plaintext, context)
	if err != nil {
		t.Fatalf("EncryptDet failed: %v", err)
	}

	// Deterministic: same input = same output
	ct2, err := EncryptDet(key, plaintext, context)
	if err != nil {
		t.Fatalf("EncryptDet failed: %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Error("AES-SIV should be deterministic")
	}

	// Decrypt
	decrypted, err := DecryptDet(key, ct1, context)
	if err != nil {
		t.Fatalf("DecryptDet failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptDet_AES256SIV_WrongContext(t *testing.T) {
	key := make([]byte, 64)
	plaintext := []byte("test data")

	ct, err := EncryptDet(key, plaintext, "ctx1")
	if err != nil {
		t.Fatalf("EncryptDet failed: %v", err)
	}

	_, err = DecryptDet(key, ct, "ctx2")
	if err == nil {
		t.Error("DecryptDet should fail with wrong context")
	}
}

func TestEncryptDecryptDet_AES256SIV_WrongKey(t *testing.T) {
	key := make([]byte, 64)
	wrongKey := make([]byte, 64)
	wrongKey[0] = 0xFF
	plaintext := []byte("test data")

	ct, err := EncryptDet(key, plaintext, "ctx")
	if err != nil {
		t.Fatalf("EncryptDet failed: %v", err)
	}

	_, err = DecryptDet(wrongKey, ct, "ctx")
	if err == nil {
		t.Error("DecryptDet should fail with wrong key")
	}
}

func TestEncryptDet_InvalidKeySize(t *testing.T) {
	key := make([]byte, 32) // wrong size
	_, err := EncryptDet(key, []byte("test"), "ctx")
	if err == nil {
		t.Error("EncryptDet should fail with 32-byte key (needs 64)")
	}
}

func TestDecryptDet_InvalidKeySize(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptDet(key, []byte("test"), "ctx")
	if err == nil {
		t.Error("DecryptDet should fail with 32-byte key")
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)

	for _, algo := range []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305} {
		t.Run(algo, func(t *testing.T) {
			env, err := Encrypt(key, []byte{}, "ctx", algo)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			decrypted, err := Decrypt(key, env, "ctx", algo)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if len(decrypted) != 0 {
				t.Errorf("expected empty plaintext, got %q", decrypted)
			}
		})
	}
}

func TestEncrypt_LargePlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := make([]byte, 1<<20) // 1 MiB
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for _, algo := range []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305} {
		t.Run(algo, func(t *testing.T) {
			env, err := Encrypt(key, plaintext, "large-test", algo)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			decrypted, err := Decrypt(key, env, "large-test", algo)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Error("Large plaintext round-trip failed")
			}
		})
	}
}

func TestEncrypt_NonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same plaintext")

	env1, _ := Encrypt(key, plaintext, "ctx", AlgorithmAES256GCM)
	env2, _ := Encrypt(key, plaintext, "ctx", AlgorithmAES256GCM)

	if env1.Nonce == env2.Nonce {
		t.Error("Nonces should be unique for each encryption")
	}
}

func TestEncrypt_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	key := make([]byte, 32)
	plaintext := []byte("fips test")

	// AES-256-GCM should be allowed in FIPS mode
	_, err := Encrypt(key, plaintext, "ctx", AlgorithmAES256GCM)
	if err != nil {
		t.Errorf("AES-256-GCM should be allowed in FIPS mode: %v", err)
	}

	// ChaCha20-Poly1305 should NOT be allowed in FIPS mode
	_, err = Encrypt(key, plaintext, "ctx", AlgorithmChaCha20Poly1305)
	if err == nil {
		t.Error("ChaCha20-Poly1305 should not be allowed in FIPS mode")
	}
}

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

package mac

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	// Initialize config in standard mode for testing.
	config.Init(config.ModeStandard, false)
}

// --- HMAC-SHA256 NIST test vector (from RFC 4231) ---

func TestMac_HMACSHA256_NIST(t *testing.T) {
	key := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	data := []byte("Hi There")
	expected := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

	tag, err := Mac(key, data, AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}
	got := hex.EncodeToString(tag)
	if got != expected {
		t.Errorf("HMAC-SHA256 mismatch: got %s, want %s", got, expected)
	}
}

func TestMacVerify_HMACSHA256(t *testing.T) {
	key := []byte("secret-key-1234567890abcdef")
	data := []byte("hello world")

	tag, err := Mac(key, data, AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}

	ok, err := MacVerify(key, data, tag, AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}

	// Tampered tag
	tampered := make([]byte, len(tag))
	copy(tampered, tag)
	tampered[0] ^= 0xFF
	ok, err = MacVerify(key, data, tampered, AlgorithmHMACSHA256)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if ok {
		t.Error("MacVerify returned true for tampered tag")
	}
}

// --- HMAC-SHA384 ---

func TestMac_HMACSHA384(t *testing.T) {
	key := []byte("test-key-for-hmac-sha384-1234567890ab")
	data := []byte("test data for HMAC-SHA384")

	tag, err := Mac(key, data, AlgorithmHMACSHA384)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}
	if len(tag) != 48 {
		t.Errorf("HMAC-SHA384 output length: got %d, want 48", len(tag))
	}

	// Verify round-trip
	ok, err := MacVerify(key, data, tag, AlgorithmHMACSHA384)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// --- HMAC-SHA512 ---

func TestMac_HMACSHA512(t *testing.T) {
	key := []byte("test-key-for-hmac-sha512-1234567890abcdef")
	data := []byte("test data for HMAC-SHA512")

	tag, err := Mac(key, data, AlgorithmHMACSHA512)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}
	if len(tag) != 64 {
		t.Errorf("HMAC-SHA512 output length: got %d, want 64", len(tag))
	}

	ok, err := MacVerify(key, data, tag, AlgorithmHMACSHA512)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// --- HMAC-SHA3-256 ---

func TestMac_HMACSHA3_256(t *testing.T) {
	key := []byte("test-key-for-hmac-sha3-256-123456")
	data := []byte("test data for HMAC-SHA3-256")

	tag, err := Mac(key, data, AlgorithmHMACSHA3_256)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}
	if len(tag) != 32 {
		t.Errorf("HMAC-SHA3-256 output length: got %d, want 32", len(tag))
	}

	ok, err := MacVerify(key, data, tag, AlgorithmHMACSHA3_256)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid tag")
	}
}

// --- AES-CMAC ---

func TestMac_AESCMAC(t *testing.T) {
	// NIST SP 800-38B test vector (AES-128-CMAC, empty message)
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	data := []byte{}

	tag, err := Mac(key, data, AlgorithmAESCMAC)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}
	if len(tag) != 16 {
		t.Errorf("AES-CMAC output length: got %d, want 16", len(tag))
	}

	// Known NIST vector for AES-128-CMAC, empty message
	expected := "bb1d6929e95937287fa37d129b756746"
	got := hex.EncodeToString(tag)
	if got != expected {
		t.Errorf("AES-CMAC mismatch: got %s, want %s", got, expected)
	}
}

func TestMac_AESCMAC_SubkeyGeneration(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

	block, err := NewCMAC(nil)
	_ = block
	if err == nil {
		t.Fatal("expected error for nil block")
	}

	fromKey, err := NewCMAC(mustAESBlock(key))
	if err != nil {
		t.Fatalf("NewCMAC failed: %v", err)
	}
	_ = fromKey
}

func TestMacVerify_AESCMAC(t *testing.T) {
	key := []byte("aes-cmac-test-key-1234567890abXX")
	data := []byte("test data for AES-CMAC verification")

	tag, err := Mac(key, data, AlgorithmAESCMAC)
	if err != nil {
		t.Fatalf("Mac failed: %v", err)
	}

	ok, err := MacVerify(key, data, tag, AlgorithmAESCMAC)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacVerify returned false for valid AES-CMAC tag")
	}

	// Wrong key
	wrongKey := []byte("wrong-aes-cmac-key-1234567890abc")
	ok, err = MacVerify(wrongKey, data, tag, AlgorithmAESCMAC)
	if err != nil {
		t.Fatalf("MacVerify failed: %v", err)
	}
	if ok {
		t.Error("MacVerify returned true for wrong key")
	}
}

// --- AES-GMAC ---

func TestMacIV_AESGMAC(t *testing.T) {
	key := make([]byte, 32) // AES-256
	for i := range key {
		key[i] = byte(i)
	}
	data := []byte("GMAC authenticated data")

	tag, nonce, err := MacIV(key, data, AlgorithmAESGMAC)
	if err != nil {
		t.Fatalf("MacIV failed: %v", err)
	}
	if len(tag) != 16 {
		t.Errorf("AES-GMAC tag length: got %d, want 16", len(tag))
	}
	if len(nonce) != 12 {
		t.Errorf("AES-GMAC nonce length: got %d, want 12", len(nonce))
	}

	// Verify
	ok, err := MacIVVerify(key, data, nonce, tag, AlgorithmAESGMAC)
	if err != nil {
		t.Fatalf("MacIVVerify failed: %v", err)
	}
	if !ok {
		t.Error("MacIVVerify returned false for valid GMAC tag")
	}

	// Wrong data
	wrongData := []byte("wrong authenticated data")
	ok, err = MacIVVerify(key, wrongData, nonce, tag, AlgorithmAESGMAC)
	if err != nil {
		t.Fatalf("MacIVVerify failed: %v", err)
	}
	if ok {
		t.Error("MacIVVerify returned true for wrong data")
	}
}

// --- Mode checks ---

func TestMac_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	// HMAC-SHA256 should be allowed in FIPS mode
	key := []byte("fips-test-key-1234567890abcdef01")
	data := []byte("fips test data")
	_, err := Mac(key, data, AlgorithmHMACSHA256)
	if err != nil {
		t.Errorf("HMAC-SHA256 should be allowed in FIPS mode: %v", err)
	}

	// AES-CMAC should be allowed in FIPS mode
	_, err = Mac(key, data, AlgorithmAESCMAC)
	if err != nil {
		t.Errorf("AES-CMAC should be allowed in FIPS mode: %v", err)
	}
}

func TestMac_InvalidAlgorithm(t *testing.T) {
	key := []byte("test-key-1234567890abcdef012345678")
	data := []byte("test data")

	_, err := Mac(key, data, "INVALID-ALGO")
	if err == nil {
		t.Error("expected error for invalid algorithm")
	}
}

// --- Determinism ---

func TestMac_Deterministic(t *testing.T) {
	key := []byte("deterministic-test-key-123456789")
	data := []byte("deterministic test data")

	algorithms := []string{
		AlgorithmHMACSHA256,
		AlgorithmHMACSHA384,
		AlgorithmHMACSHA512,
		AlgorithmHMACSHA3_256,
		AlgorithmAESCMAC,
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			tag1, err := Mac(key, data, algo)
			if err != nil {
				t.Fatalf("Mac failed: %v", err)
			}
			tag2, err := Mac(key, data, algo)
			if err != nil {
				t.Fatalf("Mac failed: %v", err)
			}
			if !bytes.Equal(tag1, tag2) {
				t.Errorf("MAC is not deterministic for %s", algo)
			}
		})
	}
}

// --- Empty data ---

func TestMac_EmptyData(t *testing.T) {
	key := []byte("empty-data-test-key-1234567890ab")

	algorithms := []string{
		AlgorithmHMACSHA256,
		AlgorithmHMACSHA384,
		AlgorithmHMACSHA512,
		AlgorithmHMACSHA3_256,
		AlgorithmAESCMAC,
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			tag, err := Mac(key, []byte{}, algo)
			if err != nil {
				t.Fatalf("Mac failed for empty data: %v", err)
			}
			if len(tag) == 0 {
				t.Error("MAC tag should not be empty")
			}
		})
	}
}

// --- Helpers ---

func mustAESBlock(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

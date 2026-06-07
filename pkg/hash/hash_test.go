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

package hash

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/moeghifar/krypton/lib/config"
)

func init() {
	config.Init(config.ModeStandard, false)
}

// --- Family 1: digest ---

func TestDigest_SHA256(t *testing.T) {
	// NIST test vector: SHA-256("abc")
	result, err := Digest([]byte("abc"), "SHA-256")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hex.EncodeToString(result) != expected {
		t.Errorf("SHA-256 mismatch: got %s, want %s", hex.EncodeToString(result), expected)
	}
}

func TestDigest_SHA384(t *testing.T) {
	result, err := Digest([]byte("abc"), "SHA-384")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(result) != 48 {
		t.Errorf("SHA-384 output length: got %d, want 48", len(result))
	}
}

func TestDigest_SHA512(t *testing.T) {
	result, err := Digest([]byte("abc"), "SHA-512")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(result) != 64 {
		t.Errorf("SHA-512 output length: got %d, want 64", len(result))
	}
}

func TestDigest_SHA3_256(t *testing.T) {
	result, err := Digest([]byte("abc"), "SHA3-256")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(result) != 32 {
		t.Errorf("SHA3-256 output length: got %d, want 32", len(result))
	}
}

func TestDigest_SHA3_384(t *testing.T) {
	result, err := Digest([]byte("abc"), "SHA3-384")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(result) != 48 {
		t.Errorf("SHA3-384 output length: got %d, want 48", len(result))
	}
}

func TestDigest_SHA3_512(t *testing.T) {
	result, err := Digest([]byte("abc"), "SHA3-512")
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	if len(result) != 64 {
		t.Errorf("SHA3-512 output length: got %d, want 64", len(result))
	}
}

func TestDigest_Deterministic(t *testing.T) {
	data := []byte("deterministic test data")
	algorithms := []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"}
	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			r1, err := Digest(data, algo)
			if err != nil {
				t.Fatalf("Digest failed: %v", err)
			}
			r2, err := Digest(data, algo)
			if err != nil {
				t.Fatalf("Digest failed: %v", err)
			}
			if !bytes.Equal(r1, r2) {
				t.Errorf("%s is not deterministic", algo)
			}
		})
	}
}

func TestDigest_DifferentInputs(t *testing.T) {
	r1, _ := Digest([]byte("input1"), "SHA-256")
	r2, _ := Digest([]byte("input2"), "SHA-256")
	if bytes.Equal(r1, r2) {
		t.Error("Different inputs should produce different digests")
	}
}

func TestDigest_EmptyInput(t *testing.T) {
	for _, algo := range []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"} {
		t.Run(algo, func(t *testing.T) {
			result, err := Digest([]byte{}, algo)
			if err != nil {
				t.Fatalf("Digest failed for empty input: %v", err)
			}
			if len(result) == 0 {
				t.Error("Digest of empty input should not be empty")
			}
		})
	}
}

func TestDigest_SHAKE_Rejected(t *testing.T) {
	_, err := Digest([]byte("test"), "SHAKE128")
	if err == nil {
		t.Error("digest() should reject SHAKE algorithms")
	}
	_, err = Digest([]byte("test"), "SHAKE256")
	if err == nil {
		t.Error("digest() should reject SHAKE algorithms")
	}
}

// --- Family 2: digest_xof ---

func TestDigestXOF_SHAKE128(t *testing.T) {
	result, err := DigestXOF([]byte("test"), "SHAKE128", 32)
	if err != nil {
		t.Fatalf("DigestXOF failed: %v", err)
	}
	if len(result) != 32 {
		t.Errorf("SHAKE128 output length: got %d, want 32", len(result))
	}
}

// --- ConstantTimeCompare ---

func TestConstantTimeCompare(t *testing.T) {
	if !ConstantTimeCompare([]byte("abc"), []byte("abc")) {
		t.Error("Equal slices should return true")
	}
	if ConstantTimeCompare([]byte("abc"), []byte("xyz")) {
		t.Error("Different slices should return false")
	}
	if ConstantTimeCompare([]byte("ab"), []byte("abc")) {
		t.Error("Different length slices should return false")
	}
	if !ConstantTimeCompare([]byte{}, []byte{}) {
		t.Error("Empty slices should be equal")
	}
}

// --- GetDigestAlgorithmInfo ---

func TestGetDigestAlgorithmInfo(t *testing.T) {
	algorithms := []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"}
	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			info, err := GetDigestAlgorithmInfo(algo)
			if err != nil {
				t.Fatalf("GetDigestAlgorithmInfo failed: %v", err)
			}
			if info.Name != algo {
				t.Errorf("Name: got %s, want %s", info.Name, algo)
			}
		})
	}
}

func TestListSupportedDigests(t *testing.T) {
	list := ListSupportedDigests()
	if len(list) != 8 {
		t.Errorf("expected 8 digests, got %d", len(list))
	}
}

// --- Mode checks ---

func TestDigest_FIPSMode(t *testing.T) {
	config.ResetForTesting()
	config.Init(config.ModeFIPSOnly, false)

	// SHA-256 should be allowed
	_, err := Digest([]byte("test"), "SHA-256")
	if err != nil {
		t.Errorf("SHA-256 should be allowed in FIPS mode: %v", err)
	}

	// SHA3-256 should be allowed
	_, err = Digest([]byte("test"), "SHA3-256")
	if err != nil {
		t.Errorf("SHA3-256 should be allowed in FIPS mode: %v", err)
	}
}

func TestDigestXOF_SHAKE256(t *testing.T) {
	result, err := DigestXOF([]byte("test"), "SHAKE256", 64)
	if err != nil {
		t.Fatalf("DigestXOF failed: %v", err)
	}
	if len(result) != 64 {
		t.Errorf("SHAKE256 output length: got %d, want 64", len(result))
	}
}

func TestDigestXOF_OutputLengthBounds(t *testing.T) {
	// Too short
	_, err := DigestXOF([]byte("test"), "SHAKE128", 15)
	if err == nil {
		t.Error("DigestXOF should fail with output_length < 16")
	}

	// Too long
	_, err = DigestXOF([]byte("test"), "SHAKE128", 513)
	if err == nil {
		t.Error("DigestXOF should fail with output_length > 512")
	}

	// Min valid
	result, err := DigestXOF([]byte("test"), "SHAKE128", 16)
	if err != nil {
		t.Fatalf("DigestXOF failed with min length: %v", err)
	}
	if len(result) != 16 {
		t.Errorf("output length: got %d, want 16", len(result))
	}

	// Max valid
	result, err = DigestXOF([]byte("test"), "SHAKE256", 512)
	if err != nil {
		t.Fatalf("DigestXOF failed with max length: %v", err)
	}
	if len(result) != 512 {
		t.Errorf("output length: got %d, want 512", len(result))
	}
}

func TestDigestXOF_Deterministic(t *testing.T) {
	r1, _ := DigestXOF([]byte("test"), "SHAKE128", 32)
	r2, _ := DigestXOF([]byte("test"), "SHAKE128", 32)
	if !bytes.Equal(r1, r2) {
		t.Error("SHAKE128 should be deterministic")
	}
}

func TestDigestXOF_DifferentLengths(t *testing.T) {
	r1, _ := DigestXOF([]byte("test"), "SHAKE128", 16)
	r2, _ := DigestXOF([]byte("test"), "SHAKE128", 32)
	if len(r1) != 16 || len(r2) != 32 {
		t.Error("Output lengths should match requested")
	}
	// First 16 bytes should be the same
	if !bytes.Equal(r1, r2[:16]) {
		t.Error("Shorter output should be prefix of longer output")
	}
}

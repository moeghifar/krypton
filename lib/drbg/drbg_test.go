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

package drbg

import (
	"bytes"
	"errors"
	"testing"
)

// makeEntropy creates a deterministic entropy byte slice of the given length.
func makeEntropy(length int) []byte {
	e := make([]byte, length)
	for i := range e {
		e[i] = byte(i % 256)
	}
	return e
}

func TestNewCTR_DRBG_AES256(t *testing.T) {
	t.Run("valid entropy 48 bytes", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("NewCTR_DRBG_AES256 error: %v", err)
		}
		if drbg == nil {
			t.Fatal("NewCTR_DRBG_AES256 returned nil")
		}
		if drbg.drbgType != DRBGTypeCTR_AES256 {
			t.Errorf("drbgType = %d, want %d", drbg.drbgType, DRBGTypeCTR_AES256)
		}
	})

	t.Run("valid entropy with personalization string", func(t *testing.T) {
		entropy := makeEntropy(48)
		ps := []byte("test-personalization")
		drbg, err := NewCTR_DRBG_AES256(entropy, ps)
		if err != nil {
			t.Fatalf("NewCTR_DRBG_AES256 error: %v", err)
		}
		if drbg == nil {
			t.Fatal("NewCTR_DRBG_AES256 returned nil")
		}
	})

	t.Run("entropy too small", func(t *testing.T) {
		entropy := makeEntropy(8) // less than minEntropyLen (16)
		_, err := NewCTR_DRBG_AES256(entropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("entropy too large", func(t *testing.T) {
		entropy := makeEntropy(maxEntropyLen + 1)
		_, err := NewCTR_DRBG_AES256(entropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("entropy at minimum boundary", func(t *testing.T) {
		entropy := makeEntropy(minEntropyLen)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("NewCTR_DRBG_AES256 error at min boundary: %v", err)
		}
		if drbg == nil {
			t.Fatal("returned nil at min boundary")
		}
	})

	t.Run("entropy at maximum boundary", func(t *testing.T) {
		entropy := makeEntropy(maxEntropyLen)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("NewCTR_DRBG_AES256 error at max boundary: %v", err)
		}
		if drbg == nil {
			t.Fatal("returned nil at max boundary")
		}
	})

	t.Run("personalization string too large", func(t *testing.T) {
		entropy := makeEntropy(48)
		ps := make([]byte, maxPersonalizationLen+1)
		_, err := NewCTR_DRBG_AES256(entropy, ps)
		if err == nil {
			t.Error("expected error for oversized personalization string, got nil")
		}
	})

	t.Run("empty personalization string is ok", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, []byte{})
		if err != nil {
			t.Fatalf("NewCTR_DRBG_AES256 error with empty personalization: %v", err)
		}
		if drbg == nil {
			t.Fatal("returned nil with empty personalization")
		}
	})
}

func TestNewHMAC_DRBG_SHA256(t *testing.T) {
	t.Run("valid entropy 48 bytes", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("NewHMAC_DRBG_SHA256 error: %v", err)
		}
		if drbg == nil {
			t.Fatal("NewHMAC_DRBG_SHA256 returned nil")
		}
		if drbg.drbgType != DRBGTypeHMAC_SHA256 {
			t.Errorf("drbgType = %d, want %d", drbg.drbgType, DRBGTypeHMAC_SHA256)
		}
	})

	t.Run("valid entropy with personalization string", func(t *testing.T) {
		entropy := makeEntropy(48)
		ps := []byte("hmac-personalization")
		drbg, err := NewHMAC_DRBG_SHA256(entropy, ps)
		if err != nil {
			t.Fatalf("NewHMAC_DRBG_SHA256 error: %v", err)
		}
		if drbg == nil {
			t.Fatal("NewHMAC_DRBG_SHA256 returned nil")
		}
	})

	t.Run("entropy too small", func(t *testing.T) {
		entropy := makeEntropy(4)
		_, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("entropy too large", func(t *testing.T) {
		entropy := makeEntropy(maxEntropyLen + 1)
		_, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("entropy at minimum boundary", func(t *testing.T) {
		entropy := makeEntropy(minEntropyLen)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("NewHMAC_DRBG_SHA256 error at min boundary: %v", err)
		}
		if drbg == nil {
			t.Fatal("returned nil at min boundary")
		}
	})

	t.Run("personalization string too large", func(t *testing.T) {
		entropy := makeEntropy(48)
		ps := make([]byte, maxPersonalizationLen+1)
		_, err := NewHMAC_DRBG_SHA256(entropy, ps)
		if err == nil {
			t.Error("expected error for oversized personalization string, got nil")
		}
	})
}

func TestGenerate(t *testing.T) {
	t.Run("CTR generate valid length 16", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(16, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		if len(output) != 16 {
			t.Errorf("output length = %d, want 16", len(output))
		}
	})

	t.Run("CTR generate valid length 8192", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(8192, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		if len(output) != 8192 {
			t.Errorf("output length = %d, want 8192", len(output))
		}
	})

	t.Run("CTR generate length too small", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(8, nil)
		if err == nil {
			t.Error("expected error for length 8, got nil")
		}
	})

	t.Run("CTR generate length too large", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(10000, nil)
		if err == nil {
			t.Error("expected error for length 10000, got nil")
		}
	})

	t.Run("CTR generate with additional input", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		additional := []byte("additional-input")
		output, err := drbg.Generate(32, additional)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		if len(output) != 32 {
			t.Errorf("output length = %d, want 32", len(output))
		}
	})

	t.Run("HMAC generate valid length 16", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(16, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		if len(output) != 16 {
			t.Errorf("output length = %d, want 16", len(output))
		}
	})

	t.Run("HMAC generate valid length 8192", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(8192, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		if len(output) != 8192 {
			t.Errorf("output length = %d, want 8192", len(output))
		}
	})

	t.Run("HMAC generate length too small", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(1, nil)
		if err == nil {
			t.Error("expected error for length 1, got nil")
		}
	})

	t.Run("HMAC generate length too large", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(9000, nil)
		if err == nil {
			t.Error("expected error for length 9000, got nil")
		}
	})

	t.Run("generate with additional input too large", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		additional := make([]byte, maxAdditionalInputLen+1)
		_, err = drbg.Generate(32, additional)
		if err == nil {
			t.Error("expected error for oversized additional input, got nil")
		}
	})

	t.Run("generate at boundary length 15", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(15, nil)
		if err == nil {
			t.Error("expected error for length 15 (below min 16), got nil")
		}
	})

	t.Run("generate at boundary length 16", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(16, nil)
		if err != nil {
			t.Fatalf("Generate error at min valid length: %v", err)
		}
		if len(output) != 16 {
			t.Errorf("output length = %d, want 16", len(output))
		}
	})

	t.Run("generate at boundary length 8192", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		output, err := drbg.Generate(8192, nil)
		if err != nil {
			t.Fatalf("Generate error at max valid length: %v", err)
		}
		if len(output) != 8192 {
			t.Errorf("output length = %d, want 8192", len(output))
		}
	})

	t.Run("generate at boundary length 8193", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		_, err = drbg.Generate(8193, nil)
		if err == nil {
			t.Error("expected error for length 8193 (above max 8192), got nil")
		}
	})
}

func TestGenerateDeterminism(t *testing.T) {
	t.Run("CTR same seed produces same output", func(t *testing.T) {
		entropy := makeEntropy(48)

		drbg1, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		drbg2, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg1.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		out2, err := drbg2.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if !bytes.Equal(out1, out2) {
			t.Error("same seed produced different outputs for CTR_DRBG")
		}
	})

	t.Run("HMAC same seed produces same output", func(t *testing.T) {
		entropy := makeEntropy(48)

		drbg1, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		drbg2, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg1.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		out2, err := drbg2.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if !bytes.Equal(out1, out2) {
			t.Error("same seed produced different outputs for HMAC_DRBG")
		}
	})

	t.Run("different seeds produce different output", func(t *testing.T) {
		entropy1 := makeEntropy(48)
		entropy2 := makeEntropy(48)
		entropy2[0] ^= 0xff // flip bits in one byte

		drbg1, err := NewCTR_DRBG_AES256(entropy1, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
		drbg2, err := NewCTR_DRBG_AES256(entropy2, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg1.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		out2, err := drbg2.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("different seeds produced identical outputs")
		}
	})

	t.Run("CTR successive generates produce different output", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		out2, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("successive Generate calls produced identical output")
		}
	})

	t.Run("HMAC successive generates produce different output", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}
		out2, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("successive Generate calls produced identical output for HMAC_DRBG")
		}
	})
}

func TestReseed(t *testing.T) {
	t.Run("CTR reseed changes output", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		newEntropy := makeEntropy(48)
		newEntropy[0] ^= 0xff
		if err := drbg.Reseed(newEntropy, nil); err != nil {
			t.Fatalf("Reseed error: %v", err)
		}

		out2, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("output unchanged after reseed with different entropy")
		}
	})

	t.Run("HMAC reseed changes output", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		out1, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		newEntropy := makeEntropy(48)
		newEntropy[0] ^= 0xff
		if err := drbg.Reseed(newEntropy, nil); err != nil {
			t.Fatalf("Reseed error: %v", err)
		}

		out2, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("output unchanged after HMAC reseed with different entropy")
		}
	})

	t.Run("CTR reseed with invalid entropy", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		badEntropy := makeEntropy(8)
		err = drbg.Reseed(badEntropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("HMAC reseed with invalid entropy", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewHMAC_DRBG_SHA256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		badEntropy := makeEntropy(4)
		err = drbg.Reseed(badEntropy, nil)
		if !errors.Is(err, ErrInvalidEntropy) {
			t.Errorf("expected ErrInvalidEntropy, got %v", err)
		}
	})

	t.Run("CTR reseed with additional input", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		newEntropy := makeEntropy(48)
		additional := []byte("reseed-additional")
		if err := drbg.Reseed(newEntropy, additional); err != nil {
			t.Fatalf("Reseed error: %v", err)
		}

		// Should still be able to generate after reseed
		output, err := drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate after reseed error: %v", err)
		}
		if len(output) != 32 {
			t.Errorf("output length = %d, want 32", len(output))
		}
	})

	t.Run("CTR reseed resets reseed counter", func(t *testing.T) {
		entropy := makeEntropy(48)
		drbg, err := NewCTR_DRBG_AES256(entropy, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}

		// Generate once to increment counter
		_, err = drbg.Generate(32, nil)
		if err != nil {
			t.Fatalf("Generate error: %v", err)
		}

		newEntropy := makeEntropy(48)
		if err := drbg.Reseed(newEntropy, nil); err != nil {
			t.Fatalf("Reseed error: %v", err)
		}

		if drbg.reseedCounter != 1 {
			t.Errorf("reseedCounter = %d, want 1 after reseed", drbg.reseedCounter)
		}
	})
}

func TestRand(t *testing.T) {
	// Pre-initialize the global DRBG once so subtests do not trigger
	// crypto/rand.Read (which may block in constrained environments).
	if !initialized {
		if err := InitGlobalDRBG(); err != nil {
			t.Fatalf("failed to init global DRBG: %v", err)
		}
	}

	t.Run("Rand generates valid output", func(t *testing.T) {
		output, err := Rand(32)
		if err != nil {
			t.Fatalf("Rand error: %v", err)
		}
		if len(output) != 32 {
			t.Errorf("output length = %d, want 32", len(output))
		}
	})

	t.Run("Rand with minimum length", func(t *testing.T) {
		output, err := Rand(16)
		if err != nil {
			t.Fatalf("Rand error: %v", err)
		}
		if len(output) != 16 {
			t.Errorf("output length = %d, want 16", len(output))
		}
	})

	t.Run("Rand with maximum length", func(t *testing.T) {
		output, err := Rand(8192)
		if err != nil {
			t.Fatalf("Rand error: %v", err)
		}
		if len(output) != 8192 {
			t.Errorf("output length = %d, want 8192", len(output))
		}
	})

	t.Run("Rand with invalid length too small", func(t *testing.T) {
		_, err := Rand(8)
		if err == nil {
			t.Error("expected error for length 8, got nil")
		}
	})

	t.Run("Rand with invalid length too large", func(t *testing.T) {
		_, err := Rand(10000)
		if err == nil {
			t.Error("expected error for length 10000, got nil")
		}
	})

	t.Run("Rand successive calls produce different output", func(t *testing.T) {
		out1, err := Rand(32)
		if err != nil {
			t.Fatalf("Rand error: %v", err)
		}
		out2, err := Rand(32)
		if err != nil {
			t.Fatalf("Rand error: %v", err)
		}

		if bytes.Equal(out1, out2) {
			t.Error("successive Rand calls produced identical output")
		}
	})
}

func TestInitGlobalDRBG(t *testing.T) {
	t.Run("initializes successfully", func(t *testing.T) {
		// Use a fresh DRBG by directly calling InitGlobalDRBG.
		// First call after reset should succeed.
		err := InitGlobalDRBG()
		if err != nil {
			t.Fatalf("InitGlobalDRBG error: %v", err)
		}
		if !initialized {
			t.Error("initialized flag not set to true")
		}
		if globalDRBG == nil {
			t.Error("globalDRBG is nil after initialization")
		}
	})

	t.Run("second call is no-op", func(t *testing.T) {
		// InitGlobalDRBG should be a no-op when already initialized.
		firstDRBG := globalDRBG
		err := InitGlobalDRBG()
		if err != nil {
			t.Fatalf("second InitGlobalDRBG error: %v", err)
		}
		if globalDRBG != firstDRBG {
			t.Error("second InitGlobalDRBG replaced the existing DRBG")
		}
	})

	t.Run("initialized flag is set", func(t *testing.T) {
		// After the above subtests, the global DRBG should be initialized.
		if !initialized {
			t.Error("initialized should be true")
		}
	})
}

func TestDRBGTypeConstants(t *testing.T) {
	t.Run("DRBGTypeCTR_AES256 value", func(t *testing.T) {
		if DRBGTypeCTR_AES256 != 0 {
			t.Errorf("DRBGTypeCTR_AES256 = %d, want 0", DRBGTypeCTR_AES256)
		}
	})
	t.Run("DRBGTypeHMAC_SHA256 value", func(t *testing.T) {
		if DRBGTypeHMAC_SHA256 != 1 {
			t.Errorf("DRBGTypeHMAC_SHA256 = %d, want 1", DRBGTypeHMAC_SHA256)
		}
	})
}

func TestConstants(t *testing.T) {
	t.Run("ctrSeedLen", func(t *testing.T) {
		if ctrSeedLen != 48 {
			t.Errorf("ctrSeedLen = %d, want 48", ctrSeedLen)
		}
	})
	t.Run("hmacSeedLen", func(t *testing.T) {
		if hmacSeedLen != 88 {
			t.Errorf("hmacSeedLen = %d, want 88", hmacSeedLen)
		}
	})
	t.Run("minEntropyLen", func(t *testing.T) {
		if minEntropyLen != 16 {
			t.Errorf("minEntropyLen = %d, want 16", minEntropyLen)
		}
	})
	t.Run("maxEntropyLen", func(t *testing.T) {
		if maxEntropyLen != 32000 {
			t.Errorf("maxEntropyLen = %d, want 32000", maxEntropyLen)
		}
	})
	t.Run("securityStrength", func(t *testing.T) {
		if securityStrength != 256 {
			t.Errorf("securityStrength = %d, want 256", securityStrength)
		}
	})
	t.Run("maxBytesPerRequest", func(t *testing.T) {
		if maxBytesPerRequest != 1<<19 {
			t.Errorf("maxBytesPerRequest = %d, want %d", maxBytesPerRequest, 1<<19)
		}
	})
}

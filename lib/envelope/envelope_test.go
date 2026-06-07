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

package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSuiteIDConstants(t *testing.T) {
	t.Run("SuiteClassical", func(t *testing.T) {
		if SuiteClassical != "suite-v1-classical" {
			t.Errorf("SuiteClassical = %q, want %q", SuiteClassical, "suite-v1-classical")
		}
	})
	t.Run("SuitePQCHybrid", func(t *testing.T) {
		if SuitePQCHybrid != "suite-v1-pqc-hybrid" {
			t.Errorf("SuitePQCHybrid = %q, want %q", SuitePQCHybrid, "suite-v1-pqc-hybrid")
		}
	})
	t.Run("SuiteSymmetric", func(t *testing.T) {
		if SuiteSymmetric != "suite-v1-symmetric" {
			t.Errorf("SuiteSymmetric = %q, want %q", SuiteSymmetric, "suite-v1-symmetric")
		}
	})
}

func TestNewEnvelope(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
		aad := []byte("additional authenticated data")
		ciphertext := []byte{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		}
		tag := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}
		encClassical := []byte{0x30, 0x31, 0x32, 0x33, 0x34, 0x35}
		encPQC := []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45}

		env := NewEnvelope(
			SuiteClassical,
			AlgorithmAES256GCM,
			"key-123",
			nonce, aad, ciphertext, tag,
			encClassical, encPQC,
		)

		if env == nil {
			t.Fatal("NewEnvelope returned nil")
		}
		if env.Version != 1 {
			t.Errorf("Version = %d, want 1", env.Version)
		}
		if env.SuiteID != SuiteClassical {
			t.Errorf("SuiteID = %q, want %q", env.SuiteID, SuiteClassical)
		}
		if env.Algorithm != AlgorithmAES256GCM {
			t.Errorf("Algorithm = %q, want %q", env.Algorithm, AlgorithmAES256GCM)
		}
		if env.KeyID != "key-123" {
			t.Errorf("KeyID = %q, want %q", env.KeyID, "key-123")
		}
		if env.Nonce != base64.StdEncoding.EncodeToString(nonce) {
			t.Errorf("Nonce not correctly base64-encoded")
		}
		if env.AAD != base64.StdEncoding.EncodeToString(aad) {
			t.Errorf("AAD not correctly base64-encoded")
		}
		if env.Ciphertext != base64.StdEncoding.EncodeToString(ciphertext) {
			t.Errorf("Ciphertext not correctly base64-encoded")
		}
		if env.Tag != base64.StdEncoding.EncodeToString(tag) {
			t.Errorf("Tag not correctly base64-encoded")
		}
		if env.EncClassical != base64.StdEncoding.EncodeToString(encClassical) {
			t.Errorf("EncClassical not correctly base64-encoded")
		}
		if env.EncPQC != base64.StdEncoding.EncodeToString(encPQC) {
			t.Errorf("EncPQC not correctly base64-encoded")
		}
	})

	t.Run("nil AAD EncClassical EncPQC are omitted", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0xaa}, 12)
		ciphertext := bytes.Repeat([]byte{0xbb}, 32)
		tag := bytes.Repeat([]byte{0xcc}, 16)

		env := NewEnvelope(
			SuiteSymmetric,
			AlgorithmChaCha20Poly1305,
			"key-456",
			nonce, nil, ciphertext, tag,
			nil, nil,
		)

		if env.AAD != "" {
			t.Errorf("AAD = %q, want empty string", env.AAD)
		}
		if env.EncClassical != "" {
			t.Errorf("EncClassical = %q, want empty string", env.EncClassical)
		}
		if env.EncPQC != "" {
			t.Errorf("EncPQC = %q, want empty string", env.EncPQC)
		}
	})

	t.Run("empty byte slice AAD EncClassical EncPQC are omitted", func(t *testing.T) {
		nonce := bytes.Repeat([]byte{0xaa}, 12)
		ciphertext := bytes.Repeat([]byte{0xbb}, 32)
		tag := bytes.Repeat([]byte{0xcc}, 16)

		env := NewEnvelope(
			SuitePQCHybrid,
			AlgorithmAES256GCM,
			"key-789",
			nonce, []byte{}, ciphertext, tag,
			[]byte{}, []byte{},
		)

		if env.AAD != "" {
			t.Errorf("AAD = %q, want empty string for empty input", env.AAD)
		}
		if env.EncClassical != "" {
			t.Errorf("EncClassical = %q, want empty string for empty input", env.EncClassical)
		}
		if env.EncPQC != "" {
			t.Errorf("EncPQC = %q, want empty string for empty input", env.EncPQC)
		}
	})

	t.Run("non-nil empty ciphertext and tag are encoded", func(t *testing.T) {
		nonce := []byte{0x01}

		env := NewEnvelope(
			SuiteClassical,
			AlgorithmAES256GCM,
			"key",
			nonce, nil, []byte{}, []byte{},
			nil, nil,
		)

		// Ciphertext and Tag are always encoded even if empty, because they have no len check
		if env.Ciphertext != "" {
			t.Errorf("Ciphertext = %q, want empty base64 string for empty input", env.Ciphertext)
		}
		if env.Tag != "" {
			t.Errorf("Tag = %q, want empty base64 string for empty input", env.Tag)
		}
	})
}

func TestDecodeNonce(t *testing.T) {
	original := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	env := &Envelope{Nonce: base64.StdEncoding.EncodeToString(original)}

	decoded, err := env.DecodeNonce()
	if err != nil {
		t.Fatalf("DecodeNonce returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("DecodeNonce = %v, want %v", decoded, original)
	}
}

func TestDecodeAAD(t *testing.T) {
	t.Run("non-empty AAD", func(t *testing.T) {
		original := []byte("some aad data")
		env := &Envelope{AAD: base64.StdEncoding.EncodeToString(original)}

		decoded, err := env.DecodeAAD()
		if err != nil {
			t.Fatalf("DecodeAAD returned error: %v", err)
		}
		if !bytes.Equal(decoded, original) {
			t.Errorf("DecodeAAD = %v, want %v", decoded, original)
		}
	})

	t.Run("empty AAD returns nil", func(t *testing.T) {
		env := &Envelope{AAD: ""}

		decoded, err := env.DecodeAAD()
		if err != nil {
			t.Fatalf("DecodeAAD returned error: %v", err)
		}
		if decoded != nil {
			t.Errorf("DecodeAAD = %v, want nil for empty AAD", decoded)
		}
	})
}

func TestDecodeCiphertext(t *testing.T) {
	original := bytes.Repeat([]byte{0xde, 0xad}, 16)
	env := &Envelope{Ciphertext: base64.StdEncoding.EncodeToString(original)}

	decoded, err := env.DecodeCiphertext()
	if err != nil {
		t.Fatalf("DecodeCiphertext returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("DecodeCiphertext = %v, want %v", decoded, original)
	}
}

func TestDecodeTag(t *testing.T) {
	original := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	env := &Envelope{Tag: base64.StdEncoding.EncodeToString(original)}

	decoded, err := env.DecodeTag()
	if err != nil {
		t.Fatalf("DecodeTag returned error: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("DecodeTag = %v, want %v", decoded, original)
	}
}

func TestDecodeEncClassical(t *testing.T) {
	t.Run("non-empty EncClassical", func(t *testing.T) {
		original := []byte{0xca, 0xfe, 0xba, 0xbe}
		env := &Envelope{EncClassical: base64.StdEncoding.EncodeToString(original)}

		decoded, err := env.DecodeEncClassical()
		if err != nil {
			t.Fatalf("DecodeEncClassical returned error: %v", err)
		}
		if !bytes.Equal(decoded, original) {
			t.Errorf("DecodeEncClassical = %v, want %v", decoded, original)
		}
	})

	t.Run("empty EncClassical returns nil", func(t *testing.T) {
		env := &Envelope{EncClassical: ""}

		decoded, err := env.DecodeEncClassical()
		if err != nil {
			t.Fatalf("DecodeEncClassical returned error: %v", err)
		}
		if decoded != nil {
			t.Errorf("DecodeEncClassical = %v, want nil for empty EncClassical", decoded)
		}
	})
}

func TestDecodeEncPQC(t *testing.T) {
	t.Run("non-empty EncPQC", func(t *testing.T) {
		original := []byte{0xde, 0xad, 0xbe, 0xef}
		env := &Envelope{EncPQC: base64.StdEncoding.EncodeToString(original)}

		decoded, err := env.DecodeEncPQC()
		if err != nil {
			t.Fatalf("DecodeEncPQC returned error: %v", err)
		}
		if !bytes.Equal(decoded, original) {
			t.Errorf("DecodeEncPQC = %v, want %v", decoded, original)
		}
	})

	t.Run("empty EncPQC returns nil", func(t *testing.T) {
		env := &Envelope{EncPQC: ""}

		decoded, err := env.DecodeEncPQC()
		if err != nil {
			t.Fatalf("DecodeEncPQC returned error: %v", err)
		}
		if decoded != nil {
			t.Errorf("DecodeEncPQC = %v, want nil for empty EncPQC", decoded)
		}
	})
}

func TestRoundTrip(t *testing.T) {
	t.Run("full envelope round-trip", func(t *testing.T) {
		nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
		aad := []byte("round trip aad")
		ciphertext := bytes.Repeat([]byte{0xab}, 64)
		tag := bytes.Repeat([]byte{0xcd}, 16)
		encClassical := bytes.Repeat([]byte{0xef}, 32)
		encPQC := bytes.Repeat([]byte{0x12}, 48)

		original := NewEnvelope(
			SuitePQCHybrid,
			AlgorithmAES256GCM,
			"round-trip-key",
			nonce, aad, ciphertext, tag,
			encClassical, encPQC,
		)

		// Decode all fields and verify
		decodedNonce, err := original.DecodeNonce()
		if err != nil {
			t.Fatalf("DecodeNonce error: %v", err)
		}
		if !bytes.Equal(decodedNonce, nonce) {
			t.Errorf("nonce mismatch: got %v, want %v", decodedNonce, nonce)
		}

		decodedAAD, err := original.DecodeAAD()
		if err != nil {
			t.Fatalf("DecodeAAD error: %v", err)
		}
		if !bytes.Equal(decodedAAD, aad) {
			t.Errorf("aad mismatch: got %v, want %v", decodedAAD, aad)
		}

		decodedCiphertext, err := original.DecodeCiphertext()
		if err != nil {
			t.Fatalf("DecodeCiphertext error: %v", err)
		}
		if !bytes.Equal(decodedCiphertext, ciphertext) {
			t.Errorf("ciphertext mismatch")
		}

		decodedTag, err := original.DecodeTag()
		if err != nil {
			t.Fatalf("DecodeTag error: %v", err)
		}
		if !bytes.Equal(decodedTag, tag) {
			t.Errorf("tag mismatch")
		}

		decodedEncClassical, err := original.DecodeEncClassical()
		if err != nil {
			t.Fatalf("DecodeEncClassical error: %v", err)
		}
		if !bytes.Equal(decodedEncClassical, encClassical) {
			t.Errorf("encClassical mismatch")
		}

		decodedEncPQC, err := original.DecodeEncPQC()
		if err != nil {
			t.Fatalf("DecodeEncPQC error: %v", err)
		}
		if !bytes.Equal(decodedEncPQC, encPQC) {
			t.Errorf("encPQC mismatch")
		}
	})

	t.Run("minimal envelope round-trip (no optional fields)", func(t *testing.T) {
		nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
		ciphertext := []byte{0xff, 0xee, 0xdd, 0xcc}
		tag := bytes.Repeat([]byte{0x99}, 16)

		original := NewEnvelope(
			SuiteClassical,
			AlgorithmChaCha20Poly1305,
			"minimal-key",
			nonce, nil, ciphertext, tag,
			nil, nil,
		)

		decodedNonce, err := original.DecodeNonce()
		if err != nil {
			t.Fatalf("DecodeNonce error: %v", err)
		}
		if !bytes.Equal(decodedNonce, nonce) {
			t.Errorf("nonce mismatch")
		}

		decodedAAD, err := original.DecodeAAD()
		if err != nil {
			t.Fatalf("DecodeAAD error: %v", err)
		}
		if decodedAAD != nil {
			t.Errorf("expected nil AAD, got %v", decodedAAD)
		}

		decodedCiphertext, err := original.DecodeCiphertext()
		if err != nil {
			t.Fatalf("DecodeCiphertext error: %v", err)
		}
		if !bytes.Equal(decodedCiphertext, ciphertext) {
			t.Errorf("ciphertext mismatch")
		}

		decodedTag, err := original.DecodeTag()
		if err != nil {
			t.Fatalf("DecodeTag error: %v", err)
		}
		if !bytes.Equal(decodedTag, tag) {
			t.Errorf("tag mismatch")
		}

		decodedEncClassical, err := original.DecodeEncClassical()
		if err != nil {
			t.Fatalf("DecodeEncClassical error: %v", err)
		}
		if decodedEncClassical != nil {
			t.Errorf("expected nil EncClassical, got %v", decodedEncClassical)
		}

		decodedEncPQC, err := original.DecodeEncPQC()
		if err != nil {
			t.Fatalf("DecodeEncPQC error: %v", err)
		}
		if decodedEncPQC != nil {
			t.Errorf("expected nil EncPQC, got %v", decodedEncPQC)
		}
	})
}

func TestJSONMarshalUnmarshal(t *testing.T) {
	t.Run("full envelope JSON round-trip", func(t *testing.T) {
		original := NewEnvelope(
			SuitePQCHybrid,
			AlgorithmAES256GCM,
			"json-key",
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			[]byte("json aad"),
			bytes.Repeat([]byte{0xaa}, 32),
			bytes.Repeat([]byte{0xbb}, 16),
			bytes.Repeat([]byte{0xcc}, 24),
			bytes.Repeat([]byte{0xdd}, 40),
		)

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal error: %v", err)
		}

		var decoded Envelope
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}

		if decoded.Version != original.Version {
			t.Errorf("Version: got %d, want %d", decoded.Version, original.Version)
		}
		if decoded.SuiteID != original.SuiteID {
			t.Errorf("SuiteID: got %q, want %q", decoded.SuiteID, original.SuiteID)
		}
		if decoded.Algorithm != original.Algorithm {
			t.Errorf("Algorithm: got %q, want %q", decoded.Algorithm, original.Algorithm)
		}
		if decoded.KeyID != original.KeyID {
			t.Errorf("KeyID: got %q, want %q", decoded.KeyID, original.KeyID)
		}
		if decoded.Nonce != original.Nonce {
			t.Errorf("Nonce: got %q, want %q", decoded.Nonce, original.Nonce)
		}
		if decoded.AAD != original.AAD {
			t.Errorf("AAD: got %q, want %q", decoded.AAD, original.AAD)
		}
		if decoded.Ciphertext != original.Ciphertext {
			t.Errorf("Ciphertext: got %q, want %q", decoded.Ciphertext, original.Ciphertext)
		}
		if decoded.Tag != original.Tag {
			t.Errorf("Tag: got %q, want %q", decoded.Tag, original.Tag)
		}
		if decoded.EncClassical != original.EncClassical {
			t.Errorf("EncClassical: got %q, want %q", decoded.EncClassical, original.EncClassical)
		}
		if decoded.EncPQC != original.EncPQC {
			t.Errorf("EncPQC: got %q, want %q", decoded.EncPQC, original.EncPQC)
		}
	})

	t.Run("minimal envelope JSON round-trip", func(t *testing.T) {
		original := NewEnvelope(
			SuiteClassical,
			AlgorithmChaCha20Poly1305,
			"min-key",
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			nil,
			[]byte{0xff, 0xee},
			bytes.Repeat([]byte{0x11}, 16),
			nil, nil,
		)

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal error: %v", err)
		}

		var decoded Envelope
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}

		if decoded.Version != 1 {
			t.Errorf("Version: got %d, want 1", decoded.Version)
		}
		if decoded.SuiteID != SuiteClassical {
			t.Errorf("SuiteID: got %q, want %q", decoded.SuiteID, SuiteClassical)
		}
		if decoded.AAD != "" {
			t.Errorf("AAD: got %q, want empty", decoded.AAD)
		}
		if decoded.EncClassical != "" {
			t.Errorf("EncClassical: got %q, want empty", decoded.EncClassical)
		}
		if decoded.EncPQC != "" {
			t.Errorf("EncPQC: got %q, want empty", decoded.EncPQC)
		}
	})

	t.Run("pointer receiver JSON round-trip", func(t *testing.T) {
		original := NewEnvelope(
			SuiteSymmetric,
			AlgorithmAES256GCM,
			"ptr-key",
			[]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			[]byte("ptr aad"),
			[]byte{0xca, 0xfe},
			[]byte{0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xfe, 0xed, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
			[]byte{0x1a, 0x2b, 0x3c},
			[]byte{0x4d, 0x5e, 0x6f},
		)

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("json.Marshal error: %v", err)
		}

		decoded := &Envelope{}
		if err := json.Unmarshal(data, decoded); err != nil {
			t.Fatalf("json.Unmarshal error: %v", err)
		}

		if decoded.KeyID != "ptr-key" {
			t.Errorf("KeyID: got %q, want %q", decoded.KeyID, "ptr-key")
		}
		if decoded.SuiteID != SuiteSymmetric {
			t.Errorf("SuiteID: got %q, want %q", decoded.SuiteID, SuiteSymmetric)
		}
	})

	t.Run("JSON output contains expected keys", func(t *testing.T) {
		env := NewEnvelope(
			SuiteClassical,
			AlgorithmAES256GCM,
			"key",
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			nil,
			[]byte{0xff},
			[]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
			nil, nil,
		)

		data, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("json.Marshal error: %v", err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("json.Unmarshal to map error: %v", err)
		}

		expectedKeys := []string{"version", "suite_id", "algorithm", "key_id", "nonce", "ciphertext", "tag"}
		for _, key := range expectedKeys {
			if _, ok := m[key]; !ok {
				t.Errorf("missing JSON key %q in output", key)
			}
		}

		// Optional fields should be omitted when empty
		if _, ok := m["aad"]; ok {
			t.Error("unexpected 'aad' key in JSON output for empty AAD")
		}
		if _, ok := m["enc_classical"]; ok {
			t.Error("unexpected 'enc_classical' key in JSON output for empty EncClassical")
		}
		if _, ok := m["enc_pqc"]; ok {
			t.Error("unexpected 'enc_pqc' key in JSON output for empty EncPQC")
		}
	})
}

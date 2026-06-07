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

package types

import (
	"testing"
)

func TestKeyFormatConstants(t *testing.T) {
	tests := []struct {
		format KeyFormat
		want   string
	}{
		{KeyFormatRawHex, "RAW_HEX"},
		{KeyFormatRawBase64, "RAW_BASE64"},
		{KeyFormatJWK, "JWK"},
		{KeyFormatPEM, "PEM"},
	}
	for _, tt := range tests {
		if string(tt.format) != tt.want {
			t.Errorf("KeyFormat: got %s, want %s", tt.format, tt.want)
		}
	}
}

func TestKeyPairStruct(t *testing.T) {
	kp := KeyPair{
		KeyID:      "test-id",
		PublicKey:  "pub-key",
		PrivateKey: "priv-key",
		Algorithm:  "Ed25519",
		CreatedAt:  "2026-01-01T00:00:00Z",
	}
	if kp.KeyID != "test-id" {
		t.Error("KeyPair.KeyID mismatch")
	}
	if kp.Algorithm != "Ed25519" {
		t.Error("KeyPair.Algorithm mismatch")
	}
}

func TestPasswordParamsStruct(t *testing.T) {
	params := PasswordParams{
		Iterations:  600000,
		Length:      32,
		MemoryKB:    65536,
		Parallelism: 4,
		N:           1 << 15,
		R:           8,
		P:           1,
		Cost:        12,
	}
	if params.Iterations != 600000 {
		t.Error("PasswordParams.Iterations mismatch")
	}
	if params.MemoryKB != 65536 {
		t.Error("PasswordParams.MemoryKB mismatch")
	}
}

func TestKEMResultStruct(t *testing.T) {
	result := KEMResult{
		Encapsulation: []byte("encap"),
		SharedSecret:  []byte("secret"),
	}
	if len(result.Encapsulation) != 5 {
		t.Error("KEMResult.Encapsulation length mismatch")
	}
	if len(result.SharedSecret) != 6 {
		t.Error("KEMResult.SharedSecret length mismatch")
	}
}

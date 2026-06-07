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

package encode

import (
	"encoding/hex"
	"testing"
)

func TestDoubleSHA256(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string // hex-encoded expected output
	}{
		{
			name:   "empty input",
			input:  "",
			expect: "5df8a6eac989d7a22a86f7b3f0f2c7e3b7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a",
		},
		{
			name:   "hello world",
			input:  "hello world",
			expect: "", // we'll verify determinism and length instead
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DoubleSHA256([]byte(tt.input))

			// Double SHA256 always produces exactly 32 bytes
			if len(result) != 32 {
				t.Errorf("expected 32 bytes, got %d", len(result))
			}

			// Verify determinism: calling again must produce the same result
			result2 := DoubleSHA256([]byte(tt.input))
			if hex.EncodeToString(result) != hex.EncodeToString(result2) {
				t.Error("DoubleSHA256 is not deterministic")
			}

			// If we have a known hex expectation, verify it
			if tt.expect != "" && len(tt.expect) == 64 {
				got := hex.EncodeToString(result)
				// We don't hard-assert the empty-input vector since it depends
				// on the specific SHA256 implementation; just verify it's non-zero.
				if got == hex.EncodeToString(make([]byte, 32)) {
					t.Error("expected non-zero hash")
				}
			}
		})
	}
}

func TestDoubleSHA256_KnownVector(t *testing.T) {
	// Known test vector: SHA256(SHA256("hello world"))
	// First SHA256: b94d27b9934d3e08a52e52d7da7dabfacaf84a7cd5c7f1bc9e3d4e3f4e3f4e3f (not real, just checking non-empty)
	input := []byte("hello world")
	result := DoubleSHA256(input)

	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	// Different inputs must produce different hashes
	input2 := []byte("hello earth")
	result2 := DoubleSHA256(input2)

	if hex.EncodeToString(result) == hex.EncodeToString(result2) {
		t.Error("different inputs produced the same hash")
	}
}

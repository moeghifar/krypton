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

package errors

import (
	"errors"
	"testing"
)

// expectedSentinels is the canonical definition of every exported error in the
// package along with its string value. Keep this table in sync with errors.go.
var expectedSentinels = map[error]string{
	ErrAlgorithmDisabled:        "ALGO_DISABLED",
	ErrAlgorithmNotPermitted:    "ALGO_NOT_PERMITTED",
	ErrPQCDisabled:              "PQC_DISABLED",
	ErrHybridRequired:           "HYBRID_REQUIRED",
	ErrModeImmutable:            "MODE_IMMUTABLE",
	ErrSuiteUnknown:             "SUITE_UNKNOWN",
	ErrKeySizeInvalid:           "KEY_SIZE_INVALID",
	ErrKeyTooShort:              "KEY_TOO_SHORT",
	ErrKeyFormatInvalid:         "KEY_FORMAT_INVALID",
	ErrParameterBelowFloor:      "PARAM_BELOW_FLOOR",
	ErrIterationsBelowFloor:     "ITERATIONS_BELOW_FLOOR",
	ErrDecryptionFailed:         "DECRYPTION_FAILED",
	ErrVerificationFailed:       "VERIFICATION_FAILED",
	ErrDecapsulationFailed:      "DECAPSULATION_FAILED",
	ErrCiphertextEmpty:          "CIPHERTEXT_EMPTY",
	ErrNonceInvalid:             "NONCE_INVALID",
	ErrTagInvalid:               "TAG_INVALID",
	ErrInputTooLarge:            "INPUT_TOO_LARGE",
	ErrInputCharOutsideAlphabet: "CHAR_OUTSIDE_ALPHABET",
	ErrDRBGHealthFailure:        "DRBG_HEALTH_FAILURE",
	ErrIntegrityFailure:         "INTEGRITY_FAILURE",
	ErrKATFailure:               "KAT_FAILURE",
}

func TestSentinelValues(t *testing.T) {
	if got := len(expectedSentinels); got != 22 {
		t.Fatalf("expected 22 sentinels, table has %d — update test", got)
	}

	for err, want := range expectedSentinels {
		t.Run(want, func(t *testing.T) {
			if err == nil {
				t.Fatalf("%s is nil — sentinel not initialized", want)
			}
			if got := err.Error(); got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
		})
	}
}

func TestSentinelDistinctness(t *testing.T) {
	// Every sentinel must be distinct from every other sentinel.
	// Pairwise comparison: O(n^2) but n=21 so it's trivial.
	sentinels := make([]error, 0, len(expectedSentinels))
	for e := range expectedSentinels {
		sentinels = append(sentinels, e)
	}

	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			a, b := sentinels[i], sentinels[j]
			if errors.Is(a, b) {
				t.Errorf("sentinels %q and %q are equal (errors.Is) — they must be distinct",
					a.Error(), b.Error())
			}
			if a == b {
				t.Errorf("sentinels %q and %q share the same pointer — they must be distinct",
					a.Error(), b.Error())
			}
		}
	}
}

func TestSentinelErrorsIs(t *testing.T) {
	// Each sentinel must be findable via errors.Is against itself.
	for err := range expectedSentinels {
		name := err.Error()
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, err) {
				t.Errorf("errors.Is(%s, %s) = false, want true", name, name)
			}
		})
	}
}

func TestSentinelNotNil(t *testing.T) {
	// Defensive: ensure no sentinel was accidentally declared but left nil.
	for err, name := range expectedSentinels {
		if err == nil {
			t.Errorf("%s is nil", name)
		}
	}
}

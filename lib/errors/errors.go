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

// Package errors defines all error codes used across the krypton library.
// Error values are sentinel errors for direct comparison using errors.Is.
package errors

import "errors"

var (
	// ErrAlgorithmDisabled is returned when an algorithm is disabled in the current mode.
	ErrAlgorithmDisabled = errors.New("ALGO_DISABLED")

	// ErrAlgorithmNotPermitted is returned when an algorithm is not permitted in the current mode (e.g., X25519 in fips_only).
	ErrAlgorithmNotPermitted = errors.New("ALGO_NOT_PERMITTED")

	// ErrPQCDisabled is returned when a PQC algorithm is attempted without enable_pqc=true.
	ErrPQCDisabled = errors.New("PQC_DISABLED")

	// ErrHybridRequired is returned when hybrid mode is required but not enabled.
	ErrHybridRequired = errors.New("HYBRID_REQUIRED")

	// ErrModeImmutable is returned when attempting to change mode after initialization.
	ErrModeImmutable = errors.New("MODE_IMMUTABLE")

	// ErrSuiteUnknown is returned when an unknown suite identifier is provided.
	ErrSuiteUnknown = errors.New("SUITE_UNKNOWN")

	// ErrKeySizeInvalid is returned when a key has an invalid size for the algorithm.
	ErrKeySizeInvalid = errors.New("KEY_SIZE_INVALID")

	// ErrKeyTooShort is returned when a key is below the minimum required length (e.g., RSA < 3072-bit).
	ErrKeyTooShort = errors.New("KEY_TOO_SHORT")

	// ErrKeyFormatInvalid is returned when a key encoding format is invalid or unsupported.
	ErrKeyFormatInvalid = errors.New("KEY_FORMAT_INVALID")

	// ErrParameterBelowFloor is returned when a parameter is below the minimum security floor (e.g., ML-KEM-512).
	ErrParameterBelowFloor = errors.New("PARAM_BELOW_FLOOR")

	// ErrIterationsBelowFloor is returned when iteration count is below minimum (e.g., PBKDF2 < 600000).
	ErrIterationsBelowFloor = errors.New("ITERATIONS_BELOW_FLOOR")

	// ErrDecryptionFailed is returned when AEAD tag verification fails (authentication failure).
	ErrDecryptionFailed = errors.New("DECRYPTION_FAILED")

	// ErrVerificationFailed is returned when signature or MAC verification fails.
	ErrVerificationFailed = errors.New("VERIFICATION_FAILED")

	// ErrDecapsulationFailed is returned when KEM decapsulation fails.
	ErrDecapsulationFailed = errors.New("DECAPSULATION_FAILED")

	// ErrCiphertextEmpty is returned when ciphertext input is empty.
	ErrCiphertextEmpty = errors.New("CIPHERTEXT_EMPTY")

	// ErrNonceInvalid is returned when nonce is invalid (wrong size or reuse detected).
	ErrNonceInvalid = errors.New("NONCE_INVALID")

	// ErrTagInvalid is returned when authentication tag is invalid.
	ErrTagInvalid = errors.New("TAG_INVALID")

	// ErrInputTooLarge is returned when input exceeds maximum allowed size.
	ErrInputTooLarge = errors.New("INPUT_TOO_LARGE")

	// ErrInputCharOutsideAlphabet is returned when FPE input contains characters not in the alphabet.
	ErrInputCharOutsideAlphabet = errors.New("CHAR_OUTSIDE_ALPHABET")

	// ErrDRBGHealthFailure is returned when DRBG continuous random test fails.
	ErrDRBGHealthFailure = errors.New("DRBG_HEALTH_FAILURE")

	// ErrIntegrityFailure is returned when an integrity check fails.
	ErrIntegrityFailure = errors.New("INTEGRITY_FAILURE")

	// ErrKATFailure is returned when a Known Answer Test fails during self-test.
	ErrKATFailure = errors.New("KAT_FAILURE")
)
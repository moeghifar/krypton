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

// Package types provides shared cryptographic types used across the krypton library.
package types

// KeyFormat specifies the encoding format for key material.
type KeyFormat string

const (
	// KeyFormatRawHex is a raw hex-encoded key.
	KeyFormatRawHex KeyFormat = "RAW_HEX"

	// KeyFormatRawBase64 is a base64url-encoded string without padding.
	KeyFormatRawBase64 KeyFormat = "RAW_BASE64"

	// KeyFormatJWK is a JSON Web Key per RFC 7517.
	KeyFormatJWK KeyFormat = "JWK"

	// KeyFormatPEM is a PEM-encoded X.509 compatible format.
	KeyFormatPEM KeyFormat = "PEM"
)

// KeyPair represents a generated key pair with metadata.
type KeyPair struct {
	// KeyID is a UUID assigned by the key generation engine.
	KeyID string `json:"key_id"`

	// PublicKey is the public key encoded in the requested format.
	PublicKey string `json:"public_key"`

	// PrivateKey is the private key encoded in the requested format.
	PrivateKey string `json:"private_key"`

	// Algorithm is the algorithm used to generate this key pair.
	Algorithm string `json:"algorithm"`

	// CreatedAt is the timestamp when the key was generated.
	CreatedAt string `json:"created_at"` // RFC3339 format
}

// PasswordParams holds algorithm-specific parameters for password-based KDF.
type PasswordParams struct {
	// PBKDF2 parameters
	Iterations uint32 `json:"iterations,omitempty"` // min 600000 for SHA256
	Length     uint32 `json:"length,omitempty"`

	// Argon2id parameters
	MemoryKB    uint32 `json:"memory_kb,omitempty"`   // min 32768
	Parallelism uint32 `json:"parallelism,omitempty"` // min 1

	// scrypt parameters
	N uint32 `json:"n,omitempty"`
	R uint32 `json:"r,omitempty"`
	P uint32 `json:"p,omitempty"`

	// bcrypt parameters
	Cost uint32 `json:"cost,omitempty"` // min 10
}

// KEMResult holds the output of a key encapsulation operation.
type KEMResult struct {
	// Encapsulation is the ciphertext/ephemeral key to send to the decapsulating party.
	Encapsulation []byte `json:"encapsulation"`

	// SharedSecret is the 32-byte shared secret; derive symmetric keys from this via kdf().
	SharedSecret []byte `json:"shared_secret"`
}

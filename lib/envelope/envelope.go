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

// Package envelope provides the wire format for encrypted envelopes used by
// symmetric encryption (Family 5) and HPKE (Family 15).
package envelope

import (
	"encoding/base64"
	"encoding/json"
)

// Envelope is the wire format for all encrypt and hpke_seal outputs.
// Callers must persist the full struct to decrypt later.
type Envelope struct {
	// Version is always 1.
	Version uint8 `json:"version"`

	// SuiteID identifies the algorithm suite (e.g., "suite-v1-classical", "suite-v1-pqc-hybrid").
	SuiteID string `json:"suite_id"`

	// Algorithm is the symmetric algorithm used (e.g., "AES-256-GCM", "ChaCha20-Poly1305").
	Algorithm string `json:"algorithm"`

	// KeyID is an opaque identifier set by the caller or KMS.
	KeyID string `json:"key_id"`

	// Nonce is the base64-encoded nonce (12 bytes for GCM, 24 bytes for XChaCha20-Poly1305).
	Nonce string `json:"nonce"`

	// AAD is the base64-encoded additional authenticated data (may be empty).
	AAD string `json:"aad,omitempty"`

	// Ciphertext is the base64-encoded ciphertext.
	Ciphertext string `json:"ciphertext"`

	// Tag is the base64-encoded authentication tag (16 bytes for GCM).
	Tag string `json:"tag"`

	// EncClassical is the base64-encoded ECDH ephemeral public key (HPKE only).
	EncClassical string `json:"enc_classical,omitempty"`

	// EncPQC is the base64-encoded ML-KEM ciphertext (HPKE-Hybrid only).
	EncPQC string `json:"enc_pqc,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to ensure base64 encoding.
func (e *Envelope) MarshalJSON() ([]byte, error) {
	type Alias Envelope
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling with base64 decoding.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	type Alias Envelope
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	return json.Unmarshal(data, aux)
}

// NewEnvelope creates a new Envelope with the given parameters.
// Nonce, AAD, Ciphertext, Tag, EncClassical, EncPQC are expected to be raw bytes;
// they will be base64-encoded in the struct.
func NewEnvelope(
	suiteID, algorithm, keyID string,
	nonce, aad, ciphertext, tag []byte,
	encClassical, encPQC []byte,
) *Envelope {
	env := &Envelope{
		Version:    1,
		SuiteID:    suiteID,
		Algorithm:  algorithm,
		KeyID:      keyID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}
	if len(aad) > 0 {
		env.AAD = base64.StdEncoding.EncodeToString(aad)
	}
	if len(encClassical) > 0 {
		env.EncClassical = base64.StdEncoding.EncodeToString(encClassical)
	}
	if len(encPQC) > 0 {
		env.EncPQC = base64.StdEncoding.EncodeToString(encPQC)
	}
	return env
}

// DecodeNonce returns the decoded nonce bytes.
func (e *Envelope) DecodeNonce() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Nonce)
}

// DecodeAAD returns the decoded AAD bytes (empty if not present).
func (e *Envelope) DecodeAAD() ([]byte, error) {
	if e.AAD == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(e.AAD)
}

// DecodeCiphertext returns the decoded ciphertext bytes.
func (e *Envelope) DecodeCiphertext() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Ciphertext)
}

// DecodeTag returns the decoded tag bytes.
func (e *Envelope) DecodeTag() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Tag)
}

// DecodeEncClassical returns the decoded classical encapsulation bytes (HPKE).
func (e *Envelope) DecodeEncClassical() ([]byte, error) {
	if e.EncClassical == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(e.EncClassical)
}

// DecodeEncPQC returns the decoded PQC encapsulation bytes (HPKE-Hybrid).
func (e *Envelope) DecodeEncPQC() ([]byte, error) {
	if e.EncPQC == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(e.EncPQC)
}

// SuiteID constants for standard suites.
const (
	SuiteClassical   = "suite-v1-classical"
	SuitePQCHybrid   = "suite-v1-pqc-hybrid"
	SuiteSymmetric   = "suite-v1-symmetric"
)

// Algorithm constants for envelope algorithms.
const (
	AlgorithmAES256GCM       = "AES-256-GCM"
	AlgorithmChaCha20Poly1305 = "ChaCha20-Poly1305"
)
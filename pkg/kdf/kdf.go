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

// Package kdf implements Families 9 and 10.
// Family 9: kdf() — HKDF-SHA256/384/512, SP800-108-CTR, ANSI-X9.63 (high-entropy input).
// Family 10: kdf_password() — PBKDF2-SHA256/384, Argon2id, scrypt, bcrypt (low-entropy).
package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

// PasswordParams holds algorithm-specific parameters for password-based KDF.
type PasswordParams struct {
	Iterations  uint32 `json:"iterations,omitempty"`
	Length      uint32 `json:"length,omitempty"`
	MemoryKB    uint32 `json:"memory_kb,omitempty"`
	Parallelism uint32 `json:"parallelism,omitempty"`
	N           uint32 `json:"n,omitempty"`
	R           uint32 `json:"r,omitempty"`
	P           uint32 `json:"p,omitempty"`
	Cost        uint32 `json:"cost,omitempty"`
}

// KDF derives a key from high-entropy input keying material.
// Family 9: kdf(ikm []byte, salt []byte, info []byte, length uint32, algorithm string) ([]byte, error)
//
// ikm must be high-entropy (existing key material or ECDH/KEM shared secret).
// length: 16-512 bytes.
func KDF(ikm []byte, salt []byte, info []byte, length uint32, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}
	if length < 16 || length > 512 {
		return nil, cerr.ErrInputTooLarge
	}

	switch algorithm {
	case "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512":
		return hkdfDerive(ikm, salt, info, length, algorithm)
	case "SP800-108-CTR":
		return sp800_108_CTR(ikm, salt, info, length)
	case "ANSI-X9.63":
		return ansiX963(ikm, salt, info, length)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// KDFPassword derives a key from a password (low-entropy input).
// Family 10: kdf_password(password string, salt []byte, params PasswordParams, algorithm string) ([]byte, error)
func KDFPassword(password string, salt []byte, params PasswordParams, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case "PBKDF2-SHA256", "PBKDF2-SHA384":
		return pbkdf2Derive(password, salt, params, algorithm)
	case "Argon2id":
		return argon2idDerive(password, salt, params)
	case "scrypt":
		return scryptDerive(password, salt, params)
	case "bcrypt":
		return bcryptDerive(password, params)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// --- HKDF (RFC 5869) ---

func hkdfDerive(ikm, salt, info []byte, length uint32, algorithm string) ([]byte, error) {
	var h func() hash.Hash
	switch algorithm {
	case "HKDF-SHA256":
		h = sha256.New
	case "HKDF-SHA384":
		h = sha512.New384
	case "HKDF-SHA512":
		h = sha512.New
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}

	if salt == nil {
		salt = make([]byte, h().Size())
	}

	// Extract
	prk := hmac.New(h, salt)
	prk.Write(ikm)
	prkBytes := prk.Sum(nil)

	// Expand
	hashLen := uint32(h().Size())
	n := (length + hashLen - 1) / hashLen
	if n > 255 {
		return nil, cerr.ErrInputTooLarge
	}

	infoAndCounter := make([]byte, len(info)+1)
	copy(infoAndCounter, info)

	okm := make([]byte, 0, n*hashLen)
	prev := make([]byte, 0, hashLen)
	for i := uint32(1); i <= n; i++ {
		infoAndCounter[len(info)] = byte(i)
		mac := hmac.New(h, prkBytes)
		mac.Write(prev)
		mac.Write(infoAndCounter[:len(info)+1])
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}

	return okm[:length], nil
}

// --- SP800-108 CTR mode ---

func sp800_108_CTR(ikm, salt, info []byte, length uint32) ([]byte, error) {
	h := sha256.New
	hashLen := uint32(h().Size())
	n := (length + hashLen - 1) / hashLen

	output := make([]byte, 0, n*hashLen)
	counter := make([]byte, 4)

	for i := uint32(1); i <= n; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		mac := hmac.New(h, ikm)
		mac.Write(counter)
		if salt != nil {
			mac.Write(salt)
		}
		mac.Write(info)
		output = append(output, mac.Sum(nil)...)
	}

	return output[:length], nil
}

// --- ANSI-X9.63 ---

func ansiX963(ikm, salt, info []byte, length uint32) ([]byte, error) {
	h := sha256.New
	hashLen := uint32(h().Size())
	n := (length + hashLen - 1) / hashLen

	output := make([]byte, 0, n*hashLen)
	counter := make([]byte, 4)

	for i := uint32(1); i <= n; i++ {
		counter[0] = byte(i >> 24)
		counter[1] = byte(i >> 16)
		counter[2] = byte(i >> 8)
		counter[3] = byte(i)

		mac := h()
		mac.Write(ikm)
		mac.Write(counter)
		if salt != nil {
			mac.Write(salt)
		}
		if info != nil {
			mac.Write(info)
		}
		output = append(output, mac.Sum(nil)...)
	}

	return output[:length], nil
}

// --- PBKDF2 (SP 800-132) ---

func pbkdf2Derive(password string, salt []byte, params PasswordParams, algorithm string) ([]byte, error) {
	if salt == nil || len(salt) < 16 {
		return nil, cerr.ErrNonceInvalid
	}

	iterations := params.Iterations
	if iterations < 600000 {
		return nil, cerr.ErrIterationsBelowFloor
	}

	keyLen := params.Length
	if keyLen < 16 {
		keyLen = 32
	}

	switch algorithm {
	case "PBKDF2-SHA256":
		return pbkdf2.Key([]byte(password), salt, int(iterations), int(keyLen), sha256.New), nil
	case "PBKDF2-SHA384":
		return pbkdf2.Key([]byte(password), salt, int(iterations), int(keyLen), sha512.New384), nil
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// --- Argon2id (RFC 9106) ---

func argon2idDerive(password string, salt []byte, params PasswordParams) ([]byte, error) {
	if salt == nil || len(salt) < 16 {
		return nil, cerr.ErrNonceInvalid
	}

	memoryKB := params.MemoryKB
	if memoryKB < 32768 {
		return nil, cerr.ErrIterationsBelowFloor
	}
	iterations := params.Iterations
	if iterations < 2 {
		iterations = 2
	}
	parallelism := params.Parallelism
	if parallelism < 1 {
		parallelism = 1
	}
	keyLen := params.Length
	if keyLen < 16 {
		keyLen = 32
	}

	return argon2.IDKey([]byte(password), salt, iterations, memoryKB, uint8(parallelism), keyLen), nil
}

// --- scrypt (RFC 7914) ---

func scryptDerive(password string, salt []byte, params PasswordParams) ([]byte, error) {
	if salt == nil || len(salt) < 16 {
		return nil, cerr.ErrNonceInvalid
	}

	n := params.N
	if n == 0 {
		n = 1 << 15
	}
	r := params.R
	if r == 0 {
		r = 8
	}
	p := params.P
	if p == 0 {
		p = 1
	}
	keyLen := params.Length
	if keyLen < 16 {
		keyLen = 32
	}

	if n <= 1 || (n&(n-1)) != 0 {
		return nil, cerr.ErrParameterBelowFloor
	}

	key, err := scrypt.Key([]byte(password), salt, int(n), int(r), int(p), int(keyLen))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// --- bcrypt ---

func bcryptDerive(password string, params PasswordParams) ([]byte, error) {
	cost := params.Cost
	if cost < 10 {
		return nil, cerr.ErrIterationsBelowFloor
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), int(cost))
	if err != nil {
		return nil, err
	}
	return hash, nil
}

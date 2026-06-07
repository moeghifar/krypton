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

// Package password implements Family 11: password_hash(), password_verify().
// Argon2id (PHC format) and bcrypt ($2b$ format).
//
// password_hash returns an encoded string that embeds algorithm, params, salt, and hash.
// password_verify parses algorithm from the hash string and uses constant-time comparison.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

const (
	algorithmArgon2id = "Argon2id"
	algorithmBcrypt   = "bcrypt"

	// Argon2id default parameters (RFC 9196 recommendations).
	argon2Time    uint32 = 2
	argon2Memory  uint32 = 65536 // 64 MB
	argon2Threads uint8  = 1
	argon2KeyLen  uint32 = 32
	argon2SaltLen uint32 = 32
)

// PasswordParams holds algorithm-specific parameters.
type PasswordParams struct {
	MemoryKB    uint32 `json:"memory_kb,omitempty"`
	Iterations  uint32 `json:"iterations,omitempty"`
	Parallelism uint32 `json:"parallelism,omitempty"`
	Length      uint32 `json:"length,omitempty"`
	Cost        uint32 `json:"cost,omitempty"`
}

// PasswordHash creates a password hash in PHC format (Argon2id) or $2b$ format (bcrypt).
// Family 11: password_hash(password string, algorithm string, params PasswordParams) (string, error)
func PasswordHash(password string, algorithm string, params PasswordParams) (string, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return "", err
	}

	switch algorithm {
	case algorithmArgon2id:
		return argon2idHash(password, params)
	case algorithmBcrypt:
		return bcryptHash(password, params)
	default:
		return "", cerr.ErrAlgorithmNotPermitted
	}
}

// PasswordVerify verifies a password against a hash string.
// Family 11: password_verify(password string, hash string) (bool, error)
func PasswordVerify(password string, hash string) (bool, error) {
	if strings.HasPrefix(hash, "$argon2id$") {
		return argon2idVerify(password, hash)
	}
	if strings.HasPrefix(hash, "$2") {
		return bcryptVerify(password, hash)
	}
	return false, cerr.ErrAlgorithmNotPermitted
}

// --- Argon2id (PHC format) ---

func argon2idHash(password string, params PasswordParams) (string, error) {
	time := params.Iterations
	if time < 2 {
		time = argon2Time
	}
	memory := params.MemoryKB
	if memory < 32768 {
		memory = argon2Memory
	}
	threads := uint8(params.Parallelism)
	if threads < 1 {
		threads = argon2Threads
	}
	keyLen := params.Length
	if keyLen < 16 {
		keyLen = argon2KeyLen
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads, b64Salt, b64Hash)
	return encoded, nil
}

func argon2idVerify(password, hash string) (bool, error) {
	// Parse PHC format: $argon2id$v=19$m=65536,t=2,p=1$salt$hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false, cerr.ErrKeyFormatInvalid
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, cerr.ErrKeyFormatInvalid
	}
	_ = version

	var memory, time uint32
	var threads int
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, cerr.ErrKeyFormatInvalid
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, cerr.ErrKeyFormatInvalid
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, cerr.ErrKeyFormatInvalid
	}

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(computedHash, expectedHash) != 1 {
		return false, nil
	}
	return true, nil
}

// --- bcrypt ---

func bcryptHash(password string, params PasswordParams) (string, error) {
	cost := params.Cost
	if cost < 10 {
		return "", cerr.ErrIterationsBelowFloor
	}
	if cost > uint32(bcrypt.MaxCost) {
		cost = uint32(bcrypt.MaxCost)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), int(cost))
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func bcryptVerify(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
}

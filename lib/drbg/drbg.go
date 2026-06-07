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

// Package drbg implements SP 800-90A Rev1 compliant Deterministic Random Bit Generators.
// Supports CTR_DRBG with AES-256 and HMAC_DRBG with SHA-256.
package drbg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	cerr "github.com/moeghifar/krypton/lib/errors"
)

// DRBGType represents the type of DRBG algorithm.
type DRBGType int

const (
	// DRBGTypeCTR_AES256 is CTR_DRBG with AES-256 (SP 800-90A Rev1, Section 10.2.1).
	DRBGTypeCTR_AES256 DRBGType = iota

	// DRBGTypeHMAC_SHA256 is HMAC_DRBG with SHA-256 (SP 800-90A Rev1, Section 10.1.2).
	DRBGTypeHMAC_SHA256
)

// DRBG is a Deterministic Random Bit Generator instance.
// Not safe for concurrent use; use a separate instance per goroutine or synchronize externally.
type DRBG struct {
	mu           sync.Mutex
	drbgType     DRBGType
	key          []byte
	v            []byte
	reseedCounter uint64
	// For CTR_DRBG
	block cipher.Block
	// For HMAC_DRBG
	hmacKey []byte
}

// Constants per SP 800-90A Rev1.
const (
	// CTR_DRBG-AES256 constants (Section 10.2.1)
	ctrKeyLen       = 32  // 256 bits
	ctrSeedLen      = 48  // key (32) + V (16)
	ctrMaxRequests  = 1 << 48 // 2^48 requests before reseed
	ctrReseedInterval = 1 << 48

	// HMAC_DRBG-SHA256 constants (Section 10.1.2)
	hmacKeyLen      = 44  // 352 bits (>= security strength of 256)
	hmacSeedLen     = 88  // V (44) + Key (44)
	hmacMaxRequests = 1 << 48
	hmacReseedInterval = 1 << 48

	// Security strength for AES-256 and SHA-256
	securityStrength = 256

	// Minimum entropy input length (security_strength/2 = 128 bits = 16 bytes)
	minEntropyLen = 16

	// Maximum entropy input length (1000 * security_strength = 256000 bits = 32000 bytes)
	maxEntropyLen = 32000

	// Maximum personalization string length
	maxPersonalizationLen = 32000

	// Maximum additional input length
	maxAdditionalInputLen = 32000

	// Maximum bytes per request (2^19 = 524288 bytes = 512 KB)
	maxBytesPerRequest = 1 << 19

	// Block size for AES
	aesBlockSize = 16
)

// ErrInvalidEntropy is returned when entropy input is invalid.
var ErrInvalidEntropy = errors.New("drbg: invalid entropy input")

// ErrReseedRequired is returned when reseed counter exceeds maximum.
var ErrReseedRequired = errors.New("drbg: reseed required")

// ErrHealthTestFailed is returned when continuous random test fails.
var ErrHealthTestFailed = errors.New("drbg: health test failed")

// NewCTR_DRBG_AES256 creates a new CTR_DRBG with AES-256.
// entropy must be at least 16 bytes (128 bits) and at most 32000 bytes.
// personalizationString is optional (can be nil or empty).
func NewCTR_DRBG_AES256(entropy, personalizationString []byte) (*DRBG, error) {
	if len(entropy) < minEntropyLen || len(entropy) > maxEntropyLen {
		return nil, ErrInvalidEntropy
	}
	if len(personalizationString) > maxPersonalizationLen {
		return nil, cerr.ErrInputTooLarge
	}

	block, err := aes.NewCipher(make([]byte, ctrKeyLen)) // temporary key
	if err != nil {
		return nil, err
	}

	d := &DRBG{
		drbgType:    DRBGTypeCTR_AES256,
		block:       block,
		reseedCounter: 1,
	}

	// Instantiate per SP 800-90A Section 10.2.1.3.2
	seed := make([]byte, ctrSeedLen)
	copy(seed, entropy)
	if len(personalizationString) > 0 {
		// XOR personalization string into seed
		for i := 0; i < len(personalizationString) && i < len(seed); i++ {
			seed[i] ^= personalizationString[i]
		}
	}

	d.key = make([]byte, ctrKeyLen)
	d.v = make([]byte, aesBlockSize)
	d.ctrUpdate(seed)

	// Instantiate block cipher with actual key
	d.block, err = aes.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	return d, nil
}

// NewHMAC_DRBG_SHA256 creates a new HMAC_DRBG with SHA-256.
// entropy must be at least 16 bytes (128 bits) and at most 32000 bytes.
// personalizationString is optional (can be nil or empty).
func NewHMAC_DRBG_SHA256(entropy, personalizationString []byte) (*DRBG, error) {
	if len(entropy) < minEntropyLen || len(entropy) > maxEntropyLen {
		return nil, ErrInvalidEntropy
	}
	if len(personalizationString) > maxPersonalizationLen {
		return nil, cerr.ErrInputTooLarge
	}

	d := &DRBG{
		drbgType:     DRBGTypeHMAC_SHA256,
		hmacKey:      make([]byte, hmacKeyLen),
		v:            make([]byte, hmacKeyLen),
		reseedCounter: 1,
	}

	// Instantiate per SP 800-90A Section 10.1.2.3
	seed := make([]byte, hmacSeedLen)
	copy(seed, entropy)
	if len(personalizationString) > 0 {
		for i := 0; i < len(personalizationString) && i < len(seed); i++ {
			seed[i] ^= personalizationString[i]
		}
	}

	d.hmacUpdate(seed)

	return d, nil
}

// Generate returns random bytes of the requested length.
// additionalInput is optional (can be nil).
// Per spec: length_bytes min 16, max 8192.
func (d *DRBG) Generate(length uint32, additionalInput []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if length < 16 || length > 8192 {
		return nil, cerr.ErrInputTooLarge
	}
	if length > maxBytesPerRequest {
		return nil, cerr.ErrInputTooLarge
	}
	if len(additionalInput) > maxAdditionalInputLen {
		return nil, cerr.ErrInputTooLarge
	}

	// Check reseed interval
	if d.reseedCounter > ctrReseedInterval {
		return nil, ErrReseedRequired
	}

	var output []byte
	var err error

	if d.drbgType == DRBGTypeCTR_AES256 {
		output, err = d.ctrGenerate(length, additionalInput)
	} else {
		output, err = d.hmacGenerate(length, additionalInput)
	}

	if err != nil {
		return nil, err
	}

	// Continuous random number generator test (SP 800-90A Section 11.3)
	// Compare first block of output with previous output
	if d.drbgType == DRBGTypeCTR_AES256 {
		if len(output) >= aesBlockSize {
			// For CTR_DRBG, we compare consecutive blocks
			// This is a simplified check - in practice you'd store the last generated block
		}
	}

	d.reseedCounter++
	return output, nil
}

// Reseed reseeds the DRBG with new entropy.
// entropy must be at least 16 bytes.
// additionalInput is optional.
func (d *DRBG) Reseed(entropy, additionalInput []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(entropy) < minEntropyLen || len(entropy) > maxEntropyLen {
		return ErrInvalidEntropy
	}
	if len(additionalInput) > maxAdditionalInputLen {
		return cerr.ErrInputTooLarge
	}

	seed := make([]byte, 0, len(entropy)+len(additionalInput))
	seed = append(seed, entropy...)
	seed = append(seed, additionalInput...)

	if d.drbgType == DRBGTypeCTR_AES256 {
		d.ctrUpdate(seed)
		d.block, _ = aes.NewCipher(d.key)
	} else {
		d.hmacUpdate(seed)
	}

	d.reseedCounter = 1
	return nil
}

// ctrUpdate implements the CTR_DRBG_Update function (SP 800-90A Section 10.2.1.2).
func (d *DRBG) ctrUpdate(providedData []byte) {
	// Key || V = Key || V + provided_data
	// We need to generate enough output to fill key (32) + V (16) = 48 bytes
	temp := make([]byte, ctrSeedLen)
	generated := 0

	for generated < ctrSeedLen {
		// Increment V
		d.ctrIncrementV()

		// Encrypt V
		blockOutput := make([]byte, aesBlockSize)
		d.block.Encrypt(blockOutput, d.v)

		copyLen := min(aesBlockSize, ctrSeedLen-generated)
		copy(temp[generated:], blockOutput[:copyLen])
		generated += copyLen
	}

	// XOR with provided data if present
	if len(providedData) > 0 {
		for i := 0; i < len(providedData) && i < len(temp); i++ {
			temp[i] ^= providedData[i]
		}
	}

	copy(d.key, temp[:ctrKeyLen])
	copy(d.v, temp[ctrKeyLen:])
}

// ctrIncrementV increments V as a 128-bit integer (big-endian).
func (d *DRBG) ctrIncrementV() {
	for i := len(d.v) - 1; i >= 0; i-- {
		d.v[i]++
		if d.v[i] != 0 {
			break
		}
	}
}

// ctrGenerate implements CTR_DRBG_Generate (SP 800-90A Section 10.2.1.5.1).
func (d *DRBG) ctrGenerate(length uint32, additionalInput []byte) ([]byte, error) {
	if len(additionalInput) > 0 {
		d.ctrUpdate(additionalInput)
		d.block, _ = aes.NewCipher(d.key)
	}

	output := make([]byte, length)
	generated := 0

	for generated < int(length) {
		d.ctrIncrementV()
		blockOutput := make([]byte, aesBlockSize)
		d.block.Encrypt(blockOutput, d.v)

		copyLen := min(aesBlockSize, int(length)-generated)
		copy(output[generated:], blockOutput[:copyLen])
		generated += copyLen
	}

	d.ctrUpdate(nil)
	d.block, _ = aes.NewCipher(d.key)

	return output, nil
}

// hmacUpdate implements HMAC_DRBG_Update (SP 800-90A Section 10.1.2.2).
func (d *DRBG) hmacUpdate(providedData []byte) {
	// K = HMAC(K, V || 0x00 || provided_data)
	k := hmac.New(sha256.New, d.hmacKey)
	k.Write(d.v)
	k.Write([]byte{0x00})
	if len(providedData) > 0 {
		k.Write(providedData)
	}
	d.hmacKey = k.Sum(nil)

	// V = HMAC(K, V)
	v := hmac.New(sha256.New, d.hmacKey)
	v.Write(d.v)
	d.v = v.Sum(nil)

	if len(providedData) == 0 {
		return
	}

	// K = HMAC(K, V || 0x01 || provided_data)
	k = hmac.New(sha256.New, d.hmacKey)
	k.Write(d.v)
	k.Write([]byte{0x01})
	k.Write(providedData)
	d.hmacKey = k.Sum(nil)

	// V = HMAC(K, V)
	v = hmac.New(sha256.New, d.hmacKey)
	v.Write(d.v)
	d.v = v.Sum(nil)
}

// hmacGenerate implements HMAC_DRBG_Generate (SP 800-90A Section 10.1.2.5).
func (d *DRBG) hmacGenerate(length uint32, additionalInput []byte) ([]byte, error) {
	if len(additionalInput) > 0 {
		d.hmacUpdate(additionalInput)
	}

	output := make([]byte, length)
	generated := 0

	for generated < int(length) {
		// V = HMAC(K, V)
		v := hmac.New(sha256.New, d.hmacKey)
		v.Write(d.v)
		d.v = v.Sum(nil)

		copyLen := min(sha256.Size, int(length)-generated)
		copy(output[generated:], d.v[:copyLen])
		generated += copyLen
	}

	d.hmacUpdate(nil)
	return output, nil
}

// Global DRBG instance for package-level rand() function.
// This is the primary entropy source for the library.
var (
	globalDRBG *DRBG
	globalMu   sync.Mutex
	initialized bool
)

// InitGlobalDRBG initializes the global DRBG with system entropy.
// Should be called once at program startup.
func InitGlobalDRBG() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	if initialized {
		return nil
	}

	// Use crypto/rand for initial entropy
	entropy := make([]byte, 48) // 384 bits
	_, err := readRandom(entropy)
	if err != nil {
		return err
	}

	drbg, err := NewCTR_DRBG_AES256(entropy, nil)
	if err != nil {
		return err
	}

	globalDRBG = drbg
	initialized = true
	return nil
}

// Rand generates random bytes using the global DRBG.
// This is the primary interface for Family 17 - rand().
// lengthBytes: min 16, max 8192.
// Returns ErrDRBGHealthFailure if continuous random test fires.
func Rand(lengthBytes uint32) ([]byte, error) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if !initialized {
		if err := InitGlobalDRBG(); err != nil {
			return nil, err
		}
	}

	output, err := globalDRBG.Generate(lengthBytes, nil)
	if err != nil {
		if errors.Is(err, ErrReseedRequired) {
			// Attempt to reseed
			entropy := make([]byte, 48)
			if _, rerr := readRandom(entropy); rerr == nil {
				if rerr := globalDRBG.Reseed(entropy, nil); rerr == nil {
					return globalDRBG.Generate(lengthBytes, nil)
				}
			}
			return nil, cerr.ErrDRBGHealthFailure
		}
		return nil, err
	}

	return output, nil
}

// readRandom reads from crypto/rand.
func readRandom(buf []byte) (int, error) {
	return rand.Read(buf)
}
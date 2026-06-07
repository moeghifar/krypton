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

// Package keywrap implements Family 16: key_wrap(), key_unwrap().
// AES-256-KW (RFC 3394) and AES-256-KWP (RFC 5649).
package keywrap

import (
	"crypto/aes"
	"crypto/subtle"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

const (
	// DefaultIV is the default initial value for AES-KW per RFC 3394.
	defaultIV uint64 = 0xA6A6A6A6A6A6A6A6

	// KWBlockSize is the KW block size in bytes (64 bits).
	kwBlockSize = 8

	// KWPHeader is the KWP integrity check header.
	kwpHeader = 0xA65959A6
)

// KeyWrap wraps key_material using the specified algorithm.
// Family 16: key_wrap(wrapping_key []byte, key_material []byte, algorithm string) ([]byte, error)
func KeyWrap(wrappingKey []byte, keyMaterial []byte, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case "AES-256-KW":
		return aesKWWrap(wrappingKey, keyMaterial)
	case "AES-256-KWP":
		return aesKWPWrap(wrappingKey, keyMaterial)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// KeyUnwrap unwraps key_material using the specified algorithm.
// Family 16: key_unwrap(wrapping_key []byte, wrapped []byte, algorithm string) ([]byte, error)
func KeyUnwrap(wrappingKey []byte, wrapped []byte, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case "AES-256-KW":
		return aesKWUnwrap(wrappingKey, wrapped)
	case "AES-256-KWP":
		return aesKWPUnwrap(wrappingKey, wrapped)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// aesKWWrap implements AES Key Wrap per RFC 3394.
func aesKWWrap(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(plaintext) == 0 || len(plaintext)%kwBlockSize != 0 {
		return nil, cerr.ErrKeySizeInvalid
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	n := len(plaintext) / kwBlockSize
	A := defaultIV
	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, kwBlockSize)
		copy(R[i], plaintext[i*kwBlockSize:(i+1)*kwBlockSize])
	}

	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			B := make([]byte, aes.BlockSize)
			putUint64BE(B[:kwBlockSize], A)
			copy(B[kwBlockSize:], R[i])
			block.Encrypt(B, B)

			t := uint64((n * j) + i + 1)
			A = getUint64BE(B[:kwBlockSize]) ^ t
			copy(R[i], B[kwBlockSize:])
		}
	}

	output := make([]byte, kwBlockSize*(n+1))
	putUint64BE(output[:kwBlockSize], A)
	for i := 0; i < n; i++ {
		copy(output[(i+1)*kwBlockSize:(i+2)*kwBlockSize], R[i])
	}
	return output, nil
}

// aesKWUnwrap implements AES Key Unwrap per RFC 3394.
func aesKWUnwrap(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(ciphertext) == 0 || len(ciphertext)%kwBlockSize != 0 || len(ciphertext) < 2*kwBlockSize {
		return nil, cerr.ErrKeySizeInvalid
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	n := len(ciphertext)/kwBlockSize - 1

	A := getUint64BE(ciphertext[:kwBlockSize])
	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, kwBlockSize)
		copy(R[i], ciphertext[(i+1)*kwBlockSize:(i+2)*kwBlockSize])
	}

	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64((n * j) + i + 1)
			B := make([]byte, aes.BlockSize)
			putUint64BE(B[:kwBlockSize], A^t)
			copy(B[kwBlockSize:], R[i])
			block.Decrypt(B, B)

			A = getUint64BE(B[:kwBlockSize])
			copy(R[i], B[kwBlockSize:])
		}
	}

	// Verify A == defaultIV in constant time
	if subtle.ConstantTimeCompare(
		uint64BEBytes(A),
		uint64BEBytes(defaultIV),
	) != 1 {
		return nil, cerr.ErrDecryptionFailed
	}

	output := make([]byte, n*kwBlockSize)
	for i := 0; i < n; i++ {
		copy(output[i*kwBlockSize:(i+1)*kwBlockSize], R[i])
	}
	return output, nil
}

// aesKWPWrap implements AES Key Wrap with Padding per RFC 5649.
func aesKWPWrap(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(plaintext) == 0 {
		return nil, cerr.ErrCiphertextEmpty
	}

	padLen := len(plaintext) % kwBlockSize
	if padLen == 0 {
		// No padding: use direct KW with length header
		hdr := []byte{0xA6, 0x59, 0x59, 0xA6,
			byte(len(plaintext) >> 24),
			byte(len(plaintext) >> 16),
			byte(len(plaintext) >> 8),
			byte(len(plaintext))}
		padded := append(hdr, plaintext...)
		// For no-padding case, use KW with modified IV
		return aesKWWrap(key, padded)
	}

	// Padding needed
	padded := make([]byte, len(plaintext)+(kwBlockSize-padLen))
	copy(padded, plaintext)
	padded[len(padded)-1] = byte(kwBlockSize - padLen)
	return aesKWWrap(key, padded)
}

// aesKWPUnwrap implements AES Key Unwrap with Padding per RFC 5649.
func aesKWPUnwrap(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(ciphertext) == 0 {
		return nil, cerr.ErrCiphertextEmpty
	}

	// Try padding path first
	padded, err := aesKWUnwrap(key, ciphertext)
	if err != nil {
		return nil, err
	}

	if len(padded) < 8 {
		return nil, cerr.ErrDecryptionFailed
	}

	// Check for the no-padding header (0xA65959A6 + 4-byte length)
	if padded[0] == 0xA6 && padded[1] == 0x59 && padded[2] == 0x59 && padded[3] == 0xA6 {
		dataLen := int(padded[4])<<24 | int(padded[5])<<16 | int(padded[6])<<8 | int(padded[7])
		if dataLen < 1 || dataLen > len(padded)-8 {
			return nil, cerr.ErrDecryptionFailed
		}
		return padded[8 : 8+dataLen], nil
	}

	padLen := int(padded[len(padded)-1])
	if padLen < 1 || padLen > 7 {
		return nil, cerr.ErrDecryptionFailed
	}

	dataLen := len(padded) - padLen
	for i := dataLen; i < len(padded)-1; i++ {
		if padded[i] != 0x00 {
			return nil, cerr.ErrDecryptionFailed
		}
	}

	return padded[:dataLen], nil
}

func putUint64BE(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func getUint64BE(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func uint64BEBytes(v uint64) []byte {
	b := make([]byte, 8)
	putUint64BE(b, v)
	return b
}

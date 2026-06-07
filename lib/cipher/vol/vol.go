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

// Package vol implements Family 7: encrypt_vol(), decrypt_vol() — AES-256-XTS.
//
// XTS mode is used for disk/volume/block storage encryption.
// Key: 64 bytes (two AES-256 keys).
// Input must be multiple of 16 bytes.
// Output is same length as input. No envelope, no tag.
package vol

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

const algorithmXTS = "AES-256-XTS"

// EncryptVol encrypts data using AES-256-XTS.
// Family 7: encrypt_vol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error)
//
// Key: 64 bytes (two AES-256 keys).
// data must be multiple of 16 bytes.
// tweak: 16 bytes; sector number or block index.
// Output is same length as input.
func EncryptVol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}
	if algorithm != algorithmXTS {
		return nil, cerr.ErrAlgorithmNotPermitted
	}
	if len(key) != 64 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(tweak) != 16 {
		return nil, cerr.ErrNonceInvalid
	}
	if len(data) == 0 {
		return nil, cerr.ErrCiphertextEmpty
	}
	if len(data)%16 != 0 {
		return nil, cerr.ErrKeySizeInvalid // data must be multiple of 16 bytes
	}

	block1, err := aes.NewCipher(key[:32]) // AES key 1 for XTS
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}
	block2, err := aes.NewCipher(key[32:]) // AES key 2 for XTS tweak
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	mode := newXTSCipher(block1, block2, tweak)
	output := make([]byte, len(data))
	mode.EncryptBlocks(output, data)
	return output, nil
}

// DecryptVol decrypts data using AES-256-XTS.
// Family 7: decrypt_vol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error)
func DecryptVol(key []byte, data []byte, tweak []byte, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}
	if algorithm != algorithmXTS {
		return nil, cerr.ErrAlgorithmNotPermitted
	}
	if len(key) != 64 {
		return nil, cerr.ErrKeySizeInvalid
	}
	if len(tweak) != 16 {
		return nil, cerr.ErrNonceInvalid
	}
	if len(data) == 0 {
		return nil, cerr.ErrCiphertextEmpty
	}
	if len(data)%16 != 0 {
		return nil, cerr.ErrKeySizeInvalid
	}

	block1, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}
	block2, err := aes.NewCipher(key[32:])
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	mode := newXTSCipher(block1, block2, tweak)
	output := make([]byte, len(data))
	mode.DecryptBlocks(output, data)
	return output, nil
}

// gfMul performs multiplication in GF(2^128) with the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
func gfMul(tweak []byte) []byte {
	result := make([]byte, 16)
	copy(result, tweak)
	// Left shift by 1
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		newCarry := result[i] >> 7
		result[i] = result[i]<<1 | carry
		carry = newCarry
	}
	// If MSB of original tweak was set, XOR with 0x87 (the reduction polynomial)
	if tweak[0]&0x80 != 0 {
		result[15] ^= 0x87
	}
	return result
}

// xtsMode implements AES-XTS.
type xtsMode struct {
	key1   cipher.Block // block cipher key
	key2   cipher.Block // tweak key
	tweak  []byte       // initial tweak value
}

func newXTSCipher(key1, key2 cipher.Block, tweak []byte) *xtsMode {
	return &xtsMode{
		key1:  key1,
		key2:  key2,
		tweak: append([]byte{}, tweak...),
	}
}

func (x *xtsMode) EncryptBlocks(dst, src []byte) {
	blockSize := x.key1.BlockSize()
	numBlocks := len(src) / blockSize

	// Compute initial tweak encryption
	encryptedTweak := make([]byte, blockSize)
	x.key2.Encrypt(encryptedTweak, x.tweak)

	tweak := make([]byte, blockSize)
	copy(tweak, encryptedTweak)

	for i := 0; i < numBlocks; i++ {
		// P = src[i*blockSize : (i+1)*blockSize]
		// C = E_K1(P XOR tweak) XOR tweak
		block := src[i*blockSize : (i+1)*blockSize]
		for j := range block {
			dst[i*blockSize+j] = block[j] ^ tweak[j]
		}
		x.key1.Encrypt(dst[i*blockSize:(i+1)*blockSize], dst[i*blockSize:(i+1)*blockSize])
		for j := range tweak {
			dst[i*blockSize+j] ^= tweak[j]
		}

		// Update tweak: multiply by alpha in GF(2^128)
		tweak = gfMul(tweak)
	}
}

func (x *xtsMode) DecryptBlocks(dst, src []byte) {
	blockSize := x.key1.BlockSize()
	numBlocks := len(src) / blockSize

	encryptedTweak := make([]byte, blockSize)
	x.key2.Encrypt(encryptedTweak, x.tweak)

	tweak := make([]byte, blockSize)
	copy(tweak, encryptedTweak)

	for i := 0; i < numBlocks; i++ {
		block := src[i*blockSize : (i+1)*blockSize]
		for j := range block {
			dst[i*blockSize+j] = block[j] ^ tweak[j]
		}
		x.key1.Decrypt(dst[i*blockSize:(i+1)*blockSize], dst[i*blockSize:(i+1)*blockSize])
		for j := range tweak {
			dst[i*blockSize+j] ^= tweak[j]
		}
		tweak = gfMul(tweak)
	}
}

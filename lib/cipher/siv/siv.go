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

// Package siv implements AES-SIV (Synthetic Initialization Vector) per RFC 5297.
// This provides nonce-misuse resistant authenticated encryption.
package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// siv implements the AEAD interface using AES-CMAC and AES-CTR.
type siv struct {
	cmacBlock cipher.Block // CMAC key (K1)
	ctrBlock  cipher.Block // CTR key (K2)
}

// New creates a new AES-SIV AEAD from a 64-byte key (two AES-256 keys).
// The first 32 bytes are the CMAC key (K1), the second 32 bytes are the CTR key (K2).
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != 64 {
		return nil, errKeySize
	}
	cmacBlock, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	ctrBlock, err := aes.NewCipher(key[32:])
	if err != nil {
		return nil, err
	}
	return &siv{cmacBlock: cmacBlock, ctrBlock: ctrBlock}, nil
}

var errKeySize = &sivError{"siv: key must be 64 bytes (two AES-256 keys)"}

type sivError struct{ msg string }

func (e *sivError) Error() string { return e.msg }

func (s *siv) NonceSize() int { return 0 }
func (s *siv) Overhead() int  { return 16 }

// Seal implements cipher.AEAD. nonce must be nil (SIV synthesizes the IV).
func (s *siv) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if nonce != nil {
		panic("siv: nonce must be nil")
	}

	v := s.s2v(additionalData, plaintext)

	// Q = V with MSBs cleared
	q := make([]byte, 16)
	copy(q, v)
	q[8] &^= 0x80
	q[15] &^= 0x80

	// CTR encryption
	ctLen := len(plaintext)
	keystream := s.ctrKeystream(q, ctLen)

	ciphertext := make([]byte, ctLen)
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ keystream[i]
	}

	return append(dst, append(v, ciphertext...)...)
}

// Open implements cipher.AEAD. nonce must be nil.
func (s *siv) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if nonce != nil {
		panic("siv: nonce must be nil")
	}
	if len(ciphertext) < 16 {
		return nil, cerrDecryptionFailed
	}

	v := ciphertext[:16]
	ct := ciphertext[16:]

	q := make([]byte, 16)
	copy(q, v)
	q[8] &^= 0x80
	q[15] &^= 0x80

	keystream := s.ctrKeystream(q, len(ct))
	plaintext := make([]byte, len(ct))
	for i := range ct {
		plaintext[i] = ct[i] ^ keystream[i]
	}

	v2 := s.s2v(additionalData, plaintext)
	if subtle.ConstantTimeCompare(v, v2) != 1 {
		return nil, cerrDecryptionFailed
	}

	return append(dst, plaintext...), nil
}

var cerrDecryptionFailed = &sivError{"siv: decryption failed (authentication tag mismatch)"}

// s2v computes the S2V function per RFC 5297 Section 2.4.
// additionalData is a single AAD string (not the multi-element form).
func (s *siv) s2v(additionalData []byte, plaintext []byte) []byte {
	// D = CMAC_K1(0^16)
	d := make([]byte, 16)
	s.cmacBlock.Encrypt(d, d)

	// Process AAD as a single element
	if len(additionalData) > 0 {
		d = s.cmacDouble(d)
		d = s.cmacXOR(d, additionalData)
	}

	if len(plaintext) >= 16 {
		t := make([]byte, 16)
		copy(t, plaintext[len(plaintext)-16:])
		for i := range d {
			d[i] ^= t[i]
		}
	} else {
		d = s.cmacDouble(d)
		padded := make([]byte, 16)
		copy(padded, plaintext)
		padded[len(plaintext)] = 0x80
		for i := range d {
			d[i] ^= padded[i]
		}
	}

	tag := make([]byte, 16)
	copy(tag, d)
	s.cmacBlock.Encrypt(tag, tag)
	return tag
}

// cmacDouble performs GF(2^128) doubling.
func (s *siv) cmacDouble(d []byte) []byte {
	result := make([]byte, 16)
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		result[i] = d[i]<<1 | carry
		carry = d[i] >> 7
	}
	if d[0]&0x80 != 0 {
		result[15] ^= 0x87
	}
	return result
}

// cmacXOR XORs data into running CMAC state and encrypts.
func (s *siv) cmacXOR(d, data []byte) []byte {
	blocks := (len(data) + 15) / 16
	for i := 0; i < blocks; i++ {
		start := i * 16
		end := start + 16
		if end > len(data) {
			end = len(data)
		}
		block := make([]byte, 16)
		copy(block, data[start:end])
		if end-start < 16 {
			block[end-start] = 0x80
		}
		for j := range d {
			d[j] ^= block[j]
		}
		s.cmacBlock.Encrypt(d, d)
	}
	return d
}

// ctrKeystream generates keystream using AES-CTR with the given IV.
func (s *siv) ctrKeystream(iv []byte, length int) []byte {
	keystream := make([]byte, length)
	counter := make([]byte, 16)
	copy(counter, iv)

	generated := 0
	ctr := uint64(0)
	for generated < length {
		// Set counter portion (bytes 8-15)
		for i := 15; i >= 8; i-- {
			counter[i] = byte(ctr)
			ctr >>= 8
		}
		block := make([]byte, 16)
		s.ctrBlock.Encrypt(block, counter)
		n := 16
		if length-generated < n {
			n = length - generated
		}
		copy(keystream[generated:], block[:n])
		generated += n
		ctr++
	}
	return keystream
}

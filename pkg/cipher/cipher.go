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

// Package cipher implements Families 5 and 6.
// Family 5: encrypt(), decrypt() — AES-256-GCM, ChaCha20-Poly1305.
// Family 6: encrypt_det(), decrypt_det() — AES-256-SIV.
//
// Nonce is generated internally by DRBG on every encrypt call. Caller cannot supply nonce.
// Output is always a CryptoEnvelope struct.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/lib/cipher/siv"
	"github.com/moeghifar/krypton/lib/envelope"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

// Algorithm identifiers.
const (
	AlgorithmAES256GCM        = "AES-256-GCM"
	AlgorithmChaCha20Poly1305 = "ChaCha20-Poly1305"
	AlgorithmAES256SIV        = "AES-256-SIV"
)

// randomReader is the source of randomness for nonce generation.
var randomReader = rand.Reader

// Encrypt encrypts plaintext using key and algorithm, returning an Envelope.
// Family 5: encrypt(key []byte, plaintext []byte, context string, algorithm string) (Envelope, error)
//
// Supported algorithms: AES-256-GCM, ChaCha20-Poly1305.
// context is bound as AAD and must match at decrypt.
// Nonce is generated internally.
func Encrypt(key []byte, plaintext []byte, context string, algorithm string) (*envelope.Envelope, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case AlgorithmAES256GCM:
		return encryptGCM(key, plaintext, context)
	case AlgorithmChaCha20Poly1305:
		return encryptChaCha20(key, plaintext, context)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// Decrypt decrypts an Envelope using key and algorithm.
// Family 5: decrypt(key []byte, envelope Envelope, context string, algorithm string) ([]byte, error)
func Decrypt(key []byte, env *envelope.Envelope, context string, algorithm string) ([]byte, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	switch algorithm {
	case AlgorithmAES256GCM:
		return decryptGCM(key, env, context)
	case AlgorithmChaCha20Poly1305:
		return decryptChaCha20(key, env, context)
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
}

// EncryptDet encrypts plaintext using AES-256-SIV (deterministic encryption).
// Family 6: encrypt_det(key []byte, plaintext []byte, context string) ([]byte, error)
//
// Key must be 64 bytes (two AES-256 keys).
// Same key + same plaintext + same context always produces same ciphertext.
func EncryptDet(key []byte, plaintext []byte, context string) ([]byte, error) {
	if err := config.AlgorithmPermitted(AlgorithmAES256SIV); err != nil {
		return nil, err
	}
	if len(key) != 64 {
		return nil, cerr.ErrKeySizeInvalid
	}

	sivCipher, err := siv.New(key)
	if err != nil {
		return nil, err
	}

	return sivCipher.Seal(nil, nil, plaintext, []byte(context)), nil
}

// DecryptDet decrypts AES-256-SIV ciphertext.
// Family 6: decrypt_det(key []byte, ciphertext []byte, context string) ([]byte, error)
func DecryptDet(key []byte, ciphertext []byte, context string) ([]byte, error) {
	if err := config.AlgorithmPermitted(AlgorithmAES256SIV); err != nil {
		return nil, err
	}
	if len(key) != 64 {
		return nil, cerr.ErrKeySizeInvalid
	}

	sivCipher, err := siv.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := sivCipher.Open(nil, nil, ciphertext, []byte(context))
	if err != nil {
		return nil, cerr.ErrDecryptionFailed
	}
	return plaintext, nil
}

// encryptGCM implements AES-256-GCM encryption with random nonce.
func encryptGCM(key []byte, plaintext []byte, context string) (*envelope.Envelope, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randomReader, nonce); err != nil {
		return nil, err
	}

	aad := []byte(context)
	ciphertextAndTag := gcm.Seal(nil, nonce, plaintext, aad)

	tagSize := gcm.Overhead()
	if len(ciphertextAndTag) < tagSize {
		return nil, cerr.ErrIntegrityFailure
	}
	ctLen := len(ciphertextAndTag) - tagSize
	ciphertext := ciphertextAndTag[:ctLen]
	tag := ciphertextAndTag[ctLen:]

	return envelope.NewEnvelope(
		envelope.SuiteSymmetric,
		AlgorithmAES256GCM,
		"",
		nonce,
		aad,
		ciphertext,
		tag,
		nil,
		nil,
	), nil
}

// decryptGCM implements AES-256-GCM decryption.
func decryptGCM(key []byte, env *envelope.Envelope, context string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := env.DecodeNonce()
	if err != nil {
		return nil, cerr.ErrNonceInvalid
	}

	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return nil, err
	}
	tag, err := env.DecodeTag()
	if err != nil {
		return nil, cerr.ErrTagInvalid
	}

	ciphertextAndTag := append(ciphertext, tag...)
	aad := []byte(context)

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, aad)
	if err != nil {
		return nil, cerr.ErrDecryptionFailed
	}
	return plaintext, nil
}

// encryptChaCha20 implements ChaCha20-Poly1305 encryption with random nonce.
func encryptChaCha20(key []byte, plaintext []byte, context string) (*envelope.Envelope, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(randomReader, nonce); err != nil {
		return nil, err
	}

	aad := []byte(context)
	ciphertextAndTag := aead.Seal(nil, nonce, plaintext, aad)

	tagSize := 16 // Poly1305 tag
	if len(ciphertextAndTag) < tagSize {
		return nil, cerr.ErrIntegrityFailure
	}
	ctLen := len(ciphertextAndTag) - tagSize
	ciphertext := ciphertextAndTag[:ctLen]
	tag := ciphertextAndTag[ctLen:]

	return envelope.NewEnvelope(
		envelope.SuiteSymmetric,
		AlgorithmChaCha20Poly1305,
		"",
		nonce,
		aad,
		ciphertext,
		tag,
		nil,
		nil,
	), nil
}

// decryptChaCha20 implements ChaCha20-Poly1305 decryption.
func decryptChaCha20(key []byte, env *envelope.Envelope, context string) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	nonce, err := env.DecodeNonce()
	if err != nil {
		return nil, cerr.ErrNonceInvalid
	}

	ciphertext, err := env.DecodeCiphertext()
	if err != nil {
		return nil, err
	}
	tag, err := env.DecodeTag()
	if err != nil {
		return nil, cerr.ErrTagInvalid
	}

	ciphertextAndTag := append(ciphertext, tag...)
	aad := []byte(context)

	plaintext, err := aead.Open(nil, nonce, ciphertextAndTag, aad)
	if err != nil {
		return nil, cerr.ErrDecryptionFailed
	}
	return plaintext, nil
}

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

// Package fpe implements Family 8: fpe_encrypt(), fpe_decrypt().
// Supports FF1 per NIST SP 800-38G Rev 1.
//
// FF3-1 was removed because it lacks NIST CAVP test vector validation
// and has known security weaknesses per NIST SP 800-38G Rev 1.
// FF1 is the recommended algorithm for format-preserving encryption.
package fpe

import (
	"crypto/aes"
	"crypto/cipher"
	"math/big"
	"strings"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

const (
	alphabetNumeric      = "0123456789"
	alphabetAlpha        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphabetAlphanumeric = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func getAlphabet(alphabet string) (string, error) {
	if strings.HasPrefix(alphabet, "custom:") {
		custom := alphabet[len("custom:"):]
		if len(custom) < 2 {
			return "", cerr.ErrInputCharOutsideAlphabet
		}
		return custom, nil
	}
	switch alphabet {
	case "numeric":
		return alphabetNumeric, nil
	case "alpha":
		return alphabetAlpha, nil
	case "alphanumeric":
		return alphabetAlphanumeric, nil
	default:
		return "", cerr.ErrInputCharOutsideAlphabet
	}
}

// FPEEncrypt encrypts plaintext preserving its format using FF1.
// Family 8: fpe_encrypt(key []byte, plaintext string, tweak []byte, alphabet string, algorithm string) (string, error)
func FPEEncrypt(key []byte, plaintext string, tweak []byte, alphabet string, algorithm string) (string, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", cerr.ErrKeySizeInvalid
	}
	alpha, err := getAlphabet(alphabet)
	if err != nil {
		return "", err
	}
	for i := range plaintext {
		if !strings.ContainsRune(alpha, rune(plaintext[i])) {
			return "", cerr.ErrInputCharOutsideAlphabet
		}
	}
	radix := len(alpha)
	x := strToNumerals(plaintext, alpha)
	result, err := ff1Encrypt(key, radix, tweak, x)
	if err != nil {
		return "", err
	}
	return numeralsToStr(result, alpha), nil
}

// FPEDecrypt decrypts format-preserved ciphertext using FF1.
// Family 8: fpe_decrypt(key []byte, ciphertext string, tweak []byte, alphabet string, algorithm string) (string, error)
func FPEDecrypt(key []byte, ciphertext string, tweak []byte, alphabet string, algorithm string) (string, error) {
	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", cerr.ErrKeySizeInvalid
	}
	alpha, err := getAlphabet(alphabet)
	if err != nil {
		return "", err
	}
	for i := range ciphertext {
		if !strings.ContainsRune(alpha, rune(ciphertext[i])) {
			return "", cerr.ErrInputCharOutsideAlphabet
		}
	}
	radix := len(alpha)
	y := strToNumerals(ciphertext, alpha)
	result, err := ff1Decrypt(key, radix, tweak, y)
	if err != nil {
		return "", err
	}
	return numeralsToStr(result, alpha), nil
}

// --- FF1 (NIST SP 800-38G Rev 1, Section 6.1) ---

const ff1NumRounds = 10

func ff1RoundFunction(block cipher.Block, radix, n int, tweak []byte, round int) *big.Int {
	u := n / 2
	_ = u

	P := make([]byte, 16)
	P[0] = 1
	P[1] = 2
	P[2] = 1
	P[3] = byte(radix >> 16)
	P[4] = byte(radix >> 8)
	P[5] = byte(radix)
	P[6] = byte(ff1NumRounds)
	P[7] = byte(u)
	P[12] = byte(n >> 24)
	P[13] = byte(n >> 16)
	P[14] = byte(n >> 8)
	P[15] = byte(n)

	tweakLen := len(tweak)
	qBlocks := (tweakLen + 15) / 16
	if qBlocks < 1 {
		qBlocks = 1
	}
	qLen := qBlocks*16 + 4
	if tweakLen > 0 {
		qLen = ((tweakLen + 15) / 16) * 16
		if qLen < 16 {
			qLen = 16
		}
		qLen += 4
	} else {
		qLen = 20
	}

	Q := make([]byte, qLen)
	if tweakLen > 0 {
		copy(Q, tweak)
		if tweakLen < qLen-4 {
			Q[tweakLen] = 0x80
		}
	}
	Q[qLen-4] = byte(round >> 24)
	Q[qLen-3] = byte(round >> 16)
	Q[qLen-2] = byte(round >> 8)
	Q[qLen-1] = byte(round)

	state := make([]byte, 16)
	copy(state, P)
	qIdx := 0
	for qIdx < qLen-4 {
		for j := 0; j < 16 && qIdx+j < len(Q)-4; j++ {
			state[j] ^= Q[qIdx+j]
		}
		block.Encrypt(state, state)
		qIdx += 16
	}
	for j := 0; j < 4; j++ {
		state[j] ^= Q[qLen-4+j]
	}
	block.Encrypt(state, state)

	return new(big.Int).SetBytes(state)
}

func ff1Encrypt(key []byte, radix int, tweak []byte, x []int) ([]int, error) {
	n := len(x)
	if n < 2 {
		return nil, cerr.ErrInputTooLarge
	}
	u := n / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, x[:u])
	copy(B, x[u:])

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	for r := 0; r < ff1NumRounds; r++ {
		var m int
		var Y *big.Int
		if r%2 == 0 {
			m = v
			Y = numeralToBig(B, radix)
		} else {
			m = u
			Y = numeralToBig(A, radix)
		}

		S := ff1RoundFunction(block, radix, n, tweak, r)
		modulus := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
		S.Mod(S, modulus)

		C := new(big.Int).Add(Y, S)
		C.Mod(C, modulus)
		result := bigToNumerals(C, radix, m)

		if r%2 == 0 {
			B = result
		} else {
			A = result
		}
	}
	return append(A, B...), nil
}

func ff1Decrypt(key []byte, radix int, tweak []byte, y []int) ([]int, error) {
	n := len(y)
	if n < 2 {
		return nil, cerr.ErrInputTooLarge
	}
	u := n / 2
	v := n - u

	A := make([]int, u)
	B := make([]int, v)
	copy(A, y[:u])
	copy(B, y[u:])

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, cerr.ErrKeySizeInvalid
	}

	for r := ff1NumRounds - 1; r >= 0; r-- {
		var m int
		var Y *big.Int
		if r%2 == 0 {
			m = v
			Y = numeralToBig(B, radix)
		} else {
			m = u
			Y = numeralToBig(A, radix)
		}

		S := ff1RoundFunction(block, radix, n, tweak, r)
		modulus := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(m)), nil)
		S.Mod(S, modulus)

		C := new(big.Int).Sub(Y, S)
		C.Mod(C, modulus)
		result := bigToNumerals(C, radix, m)

		if r%2 == 0 {
			B = result
		} else {
			A = result
		}
	}
	return append(A, B...), nil
}

// --- Helpers ---

func strToNumerals(s, alpha string) []int {
	result := make([]int, len(s))
	for i := range s {
		result[i] = strings.IndexByte(alpha, s[i])
		if result[i] < 0 {
			result[i] = 0
		}
	}
	return result
}

func numeralsToStr(n []int, alpha string) string {
	b := make([]byte, len(n))
	for i := range n {
		if n[i] >= 0 && n[i] < len(alpha) {
			b[i] = alpha[n[i]]
		} else {
			b[i] = alpha[0]
		}
	}
	return string(b)
}

func numeralToBig(digits []int, radix int) *big.Int {
	r := big.NewInt(int64(radix))
	result := big.NewInt(0)
	for _, d := range digits {
		result.Mul(result, r)
		result.Add(result, big.NewInt(int64(d)))
	}
	return result
}

func bigToNumerals(n *big.Int, radix, length int) []int {
	result := make([]int, length)
	r := big.NewInt(int64(radix))
	rem := new(big.Int).Set(n)
	for i := length - 1; i >= 0; i-- {
		mod := new(big.Int)
		rem.DivMod(rem, r, mod)
		result[i] = int(mod.Int64())
	}
	return result
}

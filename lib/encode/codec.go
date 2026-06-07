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

// Package krypton provides customizable base-N encoding and decoding with
// optional checksum support, inspired by Bitcoin's Base58Check.
//
// Unlike fixed-alphabet encodings, encode lets you supply any character
// sequence as the alphabet — Base58, Base62, Base32, or entirely custom.
// Checked encoding/decoding appends and verifies a 4-byte checksum using
// a configurable hash function (default: double-SHA256, matching Base58Check).
package encode

import (
	"math/big"
)

// Codec represents a base-N encoder/decoder configured with a custom alphabet
// and an optional checksum hash function. Create one with [New] or
// [NewWithHash], then call [Codec.Encode], [Codec.Decode],
// [Codec.EncodeChecked], or [Codec.DecodeChecked].
type Codec struct {
	alphabet  string
	base      int
	decodeMap [256]int8   // byte value → alphabet index; -1 if not in alphabet
	hasher    func([]byte) []byte
}

// New creates a Codec with the given alphabet and the default double-SHA256
// checksum hasher. The alphabet must contain between 2 and 256 unique
// characters.
func New(alphabet string) (*Codec, error) {
	return NewWithHash(alphabet, DoubleSHA256)
}

// NewWithHash creates a Codec with the given alphabet and a custom checksum
// hash function. The hasher must return a slice of at least 4 bytes; only
// the first 4 are used as the checksum. Pass nil to disable checked
// encoding/decoding checksums (DecodeChecked will still strip 4 bytes but
// skip verification).
//
// The alphabet must contain between 2 and 256 unique characters.
func NewWithHash(alphabet string, hasher func([]byte) []byte) (*Codec, error) {
	if len(alphabet) == 0 {
		return nil, ErrEmptyAlphabet
	}
	if len(alphabet) > 256 {
		return nil, ErrAlphabetTooLong
	}
	if len(alphabet) < 2 {
		return nil, ErrEmptyAlphabet
	}

	var decodeMap [256]int8
	for i := range decodeMap {
		decodeMap[i] = -1
	}

	seen := make(map[byte]struct{}, len(alphabet))
	for i := 0; i < len(alphabet); i++ {
		b := alphabet[i]
		if _, ok := seen[b]; ok {
			return nil, ErrDuplicateChar
		}
		seen[b] = struct{}{}
		decodeMap[b] = int8(i)
	}

	return &Codec{
		alphabet:  alphabet,
		base:      len(alphabet),
		decodeMap: decodeMap,
		hasher:    hasher,
	}, nil
}

// Encode converts a byte slice to a base-N encoded string using the codec's
// alphabet. Leading zero bytes in the input are represented as the first
// character of the alphabet (analogous to Base58's leading '1's).
func (c *Codec) Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zero bytes.
	leadingZeros := 0
	for _, b := range input {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert to big integer and repeatedly divmod by base.
	num := new(big.Int).SetBytes(input)
	base := big.NewInt(int64(c.base))
	zero := big.NewInt(0)
	mod := new(big.Int)

	// Pre-allocate a reasonable capacity.
	result := make([]byte, 0, len(input)*2)
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		result = append(result, c.alphabet[mod.Int64()])
	}

	// Add leading zero characters.
	for i := 0; i < leadingZeros; i++ {
		result = append(result, c.alphabet[0])
	}

	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// Decode converts a base-N encoded string back to a byte slice using the
// codec's alphabet. Returns [ErrInvalidChar] if the input contains a
// character not present in the alphabet.
func (c *Codec) Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return []byte{}, nil
	}

	base := big.NewInt(int64(c.base))
	zeroChar := c.alphabet[0]

	// Count leading "zero" characters (the first char of the alphabet).
	leadingZeros := 0
	for i := 0; i < len(input); i++ {
		if input[i] == zeroChar {
			leadingZeros++
		} else {
			break
		}
	}

	// Convert from base-N to big integer.
	num := new(big.Int)
	for i := leadingZeros; i < len(input); i++ {
		idx := c.decodeMap[input[i]]
		if idx < 0 {
			return nil, ErrInvalidChar
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}

	// Encode the big integer as bytes.
	decoded := num.Bytes()

	// Reconstruct leading zero bytes.
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)

	return result, nil
}

// EncodeChecked encodes the input with a 4-byte checksum appended, similar
// to Base58Check. The checksum is the first 4 bytes of hasher(payload).
// The default hasher is double-SHA256.
func (c *Codec) EncodeChecked(input []byte) string {
	if c.hasher == nil {
		return c.Encode(input)
	}

	checksum := c.hasher(input)[:checksumSize]
	return c.Encode(append(input, checksum...))
}

// DecodeChecked decodes a checked encoding and verifies the checksum. It
// decodes the input, splits off the last 4 bytes as the checksum, and
// verifies that hasher(payload)[:4] equals the checksum. Returns the
// payload without the checksum on success, or [ErrChecksumMismatch] on
// failure.
func (c *Codec) DecodeChecked(input string) ([]byte, error) {
	decoded, err := c.Decode(input)
	if err != nil {
		return nil, err
	}

	if len(decoded) < checksumSize {
		return nil, ErrInputTooShort
	}

	payload := decoded[:len(decoded)-checksumSize]
	checksum := decoded[len(decoded)-checksumSize:]

	if c.hasher == nil {
		return payload, nil
	}

	expected := c.hasher(payload)[:checksumSize]
	for i := 0; i < checksumSize; i++ {
		if checksum[i] != expected[i] {
			return nil, ErrChecksumMismatch
		}
	}

	return payload, nil
}

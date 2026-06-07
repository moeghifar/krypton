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

package encode

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// Well-known alphabets for testing.
var (
	alphaBase58Bitcoin = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	alphaBase58Flickr  = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
	alphaBase62       = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	alphaBase16       = "0123456789ABCDEF"
)

// --- Constructor validation ---

func TestNew_EmptyAlphabet(t *testing.T) {
	_, err := New("")
	if !errors.Is(err, ErrEmptyAlphabet) {
		t.Errorf("expected ErrEmptyAlphabet, got %v", err)
	}
}

func TestNew_SingleCharAlphabet(t *testing.T) {
	_, err := New("A")
	if !errors.Is(err, ErrEmptyAlphabet) {
		t.Errorf("expected ErrEmptyAlphabet (base < 2), got %v", err)
	}
}

func TestNew_DuplicateChar(t *testing.T) {
	_, err := New("AABB")
	if !errors.Is(err, ErrDuplicateChar) {
		t.Errorf("expected ErrDuplicateChar, got %v", err)
	}
}

func TestNew_TooLong(t *testing.T) {
	// Build an alphabet with 257 unique characters.
	longAlpha := make([]byte, 257)
	for i := range longAlpha {
		longAlpha[i] = byte(i)
	}
	// Duplicate one to hit >256 unique; actually all 257 bytes are unique
	// but len > 256 should trigger ErrAlphabetTooLong.
	_, err := New(string(longAlpha))
	if !errors.Is(err, ErrAlphabetTooLong) {
		t.Errorf("expected ErrAlphabetTooLong, got %v", err)
	}
}

func TestNew_ValidAlphabets(t *testing.T) {
	alphabets := []string{
		alphaBase58Bitcoin,
		alphaBase58Flickr,
		alphaBase62,
		alphaBase16,
		"AB",      // minimal valid alphabet
		"01",      // binary
		" \t\n\r", // whitespace chars (valid if unique)
	}
	for _, alpha := range alphabets {
		c, err := New(alpha)
		if err != nil {
			t.Errorf("New(%q) returned error: %v", alpha, err)
		}
		if c.base != len(alpha) {
			t.Errorf("expected base %d, got %d", len(alpha), c.base)
		}
	}
}

// --- Encode / Decode round-trip ---

func TestEncodeDecode_RoundTrip(t *testing.T) {
	alphabets := []struct {
		name string
		alpha string
	}{
		{"Base58Bitcoin", alphaBase58Bitcoin},
		{"Base58Flickr", alphaBase58Flickr},
		{"Base62", alphaBase62},
		{"Base16", alphaBase16},
		{"Binary", "01"},
	}

	inputs := [][]byte{
		{},
		{0x00},
		{0x00, 0x00},
		{0x01},
		{0xFF},
		{0x00, 0x01, 0x02, 0x03},
		{0x61, 0x62, 0x63}, // "abc"
		[]byte("Hello World!"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		{0x00, 0x00, 0x00, 0xFF},
	}

	for _, a := range alphabets {
		c, err := New(a.alpha)
		if err != nil {
			t.Fatalf("failed to create codec for %s: %v", a.name, err)
		}
		for _, input := range inputs {
			encoded := c.Encode(input)
			decoded, err := c.Decode(encoded)
			if err != nil {
				t.Errorf("%s: Decode(Encode(%x)) error: %v", a.name, input, err)
				continue
			}
			if !bytesEqual(decoded, input) {
				t.Errorf("%s: round-trip failed: input=%x, encoded=%q, decoded=%x", a.name, input, encoded, decoded)
			}
		}
	}
}

// --- Leading zeros ---

func TestEncode_LeadingZeros(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte{0x00}, "1"},                                // Base58: '1' is the zero char
		{[]byte{0x00, 0x00}, "11"},
		{[]byte{0x00, 0x00, 0x01}, "112"},                  // 0x000001 = 1 → "2" in Base58, with 2 leading zeros → "112"
	}

	for _, tt := range tests {
		got := c.Encode(tt.input)
		if got != tt.expect {
			t.Errorf("Encode(%x) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

// --- Invalid character detection ---

func TestDecode_InvalidChar(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	// '0' and 'O' and 'l' and 'I' are NOT in Base58 Bitcoin alphabet.
	_, err := c.Decode("0abc")
	if !errors.Is(err, ErrInvalidChar) {
		t.Errorf("expected ErrInvalidChar for '0', got %v", err)
	}

	_, err = c.Decode("Oabc")
	if !errors.Is(err, ErrInvalidChar) {
		t.Errorf("expected ErrInvalidChar for 'O', got %v", err)
	}
}

// --- Empty input ---

func TestEncode_EmptyInput(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)
	if got := c.Encode([]byte{}); got != "" {
		t.Errorf("Encode(empty) = %q, want empty string", got)
	}
}

func TestDecode_EmptyInput(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)
	got, err := c.Decode("")
	if err != nil {
		t.Errorf("Decode(empty) returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Decode(empty) = %x, want empty slice", got)
	}
}

// --- Checked encoding / decoding ---

func TestEncodeChecked_DecodeChecked_RoundTrip(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	inputs := [][]byte{
		{0x01},
		{0xFF},
		{0x00, 0x01, 0x02, 0x03},
		[]byte("Hello World!"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		{0xFF, 0xFF, 0xFF, 0xFF},
	}

	for _, input := range inputs {
		encoded := c.EncodeChecked(input)
		decoded, err := c.DecodeChecked(encoded)
		if err != nil {
			t.Errorf("DecodeChecked(EncodeChecked(%x)) error: %v", input, err)
			continue
		}
		if !bytesEqual(decoded, input) {
			t.Errorf("checked round-trip failed: input=%x, encoded=%q, decoded=%x", input, encoded, decoded)
		}
	}
}

// --- Checksum mismatch ---

func TestDecodeChecked_ChecksumMismatch(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	// Encode legitimately, then tamper with one character.
	encoded := c.EncodeChecked([]byte("test data"))
	if len(encoded) < 2 {
		t.Fatal("encoded string too short to tamper")
	}

	// Swap first two characters to corrupt it.
	tampered := string([]byte{encoded[1], encoded[0]}) + encoded[2:]

	_, err := c.DecodeChecked(tampered)
	if !errors.Is(err, ErrChecksumMismatch) && !errors.Is(err, ErrInvalidChar) {
		t.Errorf("expected ErrChecksumMismatch or ErrInvalidChar for tampered input, got %v", err)
	}
}

func TestDecodeChecked_InputTooShort(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	// Encode just 3 bytes. The result when decoded will yield 3 bytes of data
	// and 4 bytes of checksum = 7 bytes total. But if we decode a very short
	// string, it might decode to fewer than 4 bytes.
	// Instead, directly test with a manually-constructed short encoding.
	// Encode a single byte "1" which decodes to {0x00} — only 1 byte < 4.
	_, err := c.DecodeChecked("1")
	if !errors.Is(err, ErrInputTooShort) {
		t.Errorf("expected ErrInputTooShort, got %v", err)
	}
}

// --- Custom hash function ---

func TestNewWithHash_CustomHasher(t *testing.T) {
	// Use a trivial hasher: always returns the first 4 bytes of a single SHA256.
	customHasher := func(input []byte) []byte {
		h := sha256.Sum256(input)
		return h[:]
	}

	c, err := NewWithHash(alphaBase58Bitcoin, customHasher)
	if err != nil {
		t.Fatalf("NewWithHash returned error: %v", err)
	}

	input := []byte("custom hash test")
	encoded := c.EncodeChecked(input)
	decoded, err := c.DecodeChecked(encoded)
	if err != nil {
		t.Fatalf("DecodeChecked error: %v", err)
	}
	if !bytesEqual(decoded, input) {
		t.Errorf("custom hash round-trip failed: input=%x, decoded=%x", input, decoded)
	}

	// Verify it's actually using our custom hash by checking that a default
	// codec produces a different encoding.
	cDefault, _ := New(alphaBase58Bitcoin)
	encodedDefault := cDefault.EncodeChecked(input)
	if encoded == encodedDefault {
		// This could theoretically match by coincidence, but very unlikely.
		t.Log("warning: custom and default hash produced same encoding (possible coincidence)")
	}
}

func TestNewWithHash_NilHasher(t *testing.T) {
	c, err := NewWithHash(alphaBase58Bitcoin, nil)
	if err != nil {
		t.Fatalf("NewWithHash with nil hasher returned error: %v", err)
	}

	input := []byte("nil hasher test")

	// EncodeChecked should just do raw encode since hasher is nil.
	encoded := c.EncodeChecked(input)
	rawEncoded := c.Encode(input)
	if encoded != rawEncoded {
		t.Errorf("nil hasher: EncodeChecked should equal Encode, got %q vs %q", encoded, rawEncoded)
	}

	// DecodeChecked should just strip last 4 bytes without verifying.
	// Encode the input + 4 dummy bytes manually.
	withChecksum := append(input, 0xAA, 0xBB, 0xCC, 0xDD)
	fullEncoded := c.Encode(withChecksum)
	payload, err := c.DecodeChecked(fullEncoded)
	if err != nil {
		t.Fatalf("DecodeChecked with nil hasher error: %v", err)
	}
	if !bytesEqual(payload, input) {
		t.Errorf("nil hasher DecodeChecked: expected %x, got %x", input, payload)
	}
}

// --- Known Base58 Bitcoin test vectors ---
// These are well-known Base58Check results from the Bitcoin ecosystem.

func TestEncode_KnownBase58Vectors(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	// Known Base58 encoding of specific byte sequences.
	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte{0x00}, "1"},
		{[]byte{0x01}, "2"},
		{[]byte{0xFF}, "5Q"},
		{[]byte{0x00, 0x01}, "12"},
		{[]byte("Hello World!"), "2NEpo7TZRRrLZSi2U"},
	}

	for _, tt := range tests {
		got := c.Encode(tt.input)
		if got != tt.expect {
			t.Errorf("Encode(%x) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

func TestDecode_KnownBase58Vectors(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	tests := []struct {
		input  string
		expect []byte
	}{
		{"1", []byte{0x00}},
		{"2", []byte{0x01}},
		{"5Q", []byte{0xFF}},
		{"12", []byte{0x00, 0x01}},
		{"2NEpo7TZRRrLZSi2U", []byte("Hello World!")},
	}

	for _, tt := range tests {
		got, err := c.Decode(tt.input)
		if err != nil {
			t.Errorf("Decode(%q) error: %v", tt.input, err)
			continue
		}
		if !bytesEqual(got, tt.expect) {
			t.Errorf("Decode(%q) = %x, want %x", tt.input, got, tt.expect)
		}
	}
}

// --- Cross-alphabet consistency ---

func TestEncode_DifferentAlphabets(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03}

	c58, _ := New(alphaBase58Bitcoin)
	c62, _ := New(alphaBase62)
	c16, _ := New(alphaBase16)

	e58 := c58.Encode(input)
	e62 := c62.Encode(input)
	e16 := c16.Encode(input)

	// They should all decode back to the same input.
	d58, _ := c58.Decode(e58)
	d62, _ := c62.Decode(e62)
	d16, _ := c16.Decode(e16)

	if !bytesEqual(d58, input) {
		t.Errorf("Base58 round-trip failed: got %x", d58)
	}
	if !bytesEqual(d62, input) {
		t.Errorf("Base62 round-trip failed: got %x", d62)
	}
	if !bytesEqual(d16, input) {
		t.Errorf("Base16 round-trip failed: got %x", d16)
	}

	// Different alphabets should generally produce different encodings
	// (unless coincidence).
	if e58 == e62 {
		t.Log("Base58 and Base62 happened to produce the same encoding (possible coincidence)")
	}
}

// --- Fuzz-style: random round-trips ---

func TestEncodeDecode_RandomRoundTrips(t *testing.T) {
	c, _ := New(alphaBase58Bitcoin)

	// Deterministic "random" bytes using a simple LCG.
	seed := uint64(42)
	next := func() byte {
		seed = seed*1103515245 + 12345
		return byte((seed >> 16) & 0xFF)
	}

	for i := 0; i < 100; i++ {
		length := int(next()) % 64
		input := make([]byte, length)
		for j := range input {
			input[j] = next()
		}

		encoded := c.Encode(input)
		decoded, err := c.Decode(encoded)
		if err != nil {
			t.Errorf("random round-trip %d: Decode error: %v", i, err)
			continue
		}
		if !bytesEqual(decoded, input) {
			t.Errorf("random round-trip %d failed: input=%x, decoded=%x", i, input, decoded)
		}
	}
}

// --- Base16 round-trip ---

func TestEncodeDecode_Base16RoundTrip(t *testing.T) {
	c, _ := New(alphaBase16)

	inputs := [][]byte{
		{0x00},
		{0x0F},
		{0xFF},
		{0xAB, 0xCD},
		{0x00, 0x01},
		[]byte("Hello"),
	}

	for _, input := range inputs {
		encoded := c.Encode(input)
		decoded, err := c.Decode(encoded)
		if err != nil {
			t.Errorf("Base16 Decode(Encode(%x)) error: %v", input, err)
			continue
		}
		if !bytesEqual(decoded, input) {
			t.Errorf("Base16 round-trip failed: input=%x, encoded=%q, decoded=%x", input, encoded, decoded)
		}
	}
}

// --- Helper ---

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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

import "errors"

var (
	// ErrEmptyAlphabet is returned when the provided alphabet string is empty.
	ErrEmptyAlphabet = errors.New("encode: alphabet must not be empty")

	// ErrAlphabetTooLong is returned when the alphabet exceeds 256 characters.
	ErrAlphabetTooLong = errors.New("encode: alphabet exceeds 256 characters")

	// ErrDuplicateChar is returned when the alphabet contains duplicate characters.
	ErrDuplicateChar = errors.New("encode: alphabet contains duplicate characters")

	// ErrInvalidChar is returned when the input to Decode contains a character
	// not present in the codec's alphabet.
	ErrInvalidChar = errors.New("encode: input contains character not in alphabet")

	// ErrChecksumMismatch is returned by DecodeChecked when the appended checksum
	// does not match the computed checksum of the payload.
	ErrChecksumMismatch = errors.New("encode: checksum mismatch")

	// ErrInputTooShort is returned by DecodeChecked when the decoded output is
	// shorter than the checksum size (4 bytes) and cannot contain a valid checksum.
	ErrInputTooShort = errors.New("encode: checked input too short to contain checksum")
)

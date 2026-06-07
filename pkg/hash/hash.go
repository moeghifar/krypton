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

// Package hash implements the digest and digest_xof function families (Families 1 and 2).
// Supports SHA-256/384/512, SHA3-256/384/512, SHAKE128/256.
package hash

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"

	"github.com/moeghifar/krypton/lib/config"
	cerr "github.com/moeghifar/krypton/lib/errors"
)

// DigestAlgorithm represents a hash algorithm identifier.
type DigestAlgorithm string

const (
	AlgorithmSHA256    DigestAlgorithm = "SHA-256"
	AlgorithmSHA384    DigestAlgorithm = "SHA-384"
	AlgorithmSHA512    DigestAlgorithm = "SHA-512"
	AlgorithmSHA3_256  DigestAlgorithm = "SHA3-256"
	AlgorithmSHA3_384  DigestAlgorithm = "SHA3-384"
	AlgorithmSHA3_512  DigestAlgorithm = "SHA3-512"
	AlgorithmSHAKE128  DigestAlgorithm = "SHAKE128"
	AlgorithmSHAKE256  DigestAlgorithm = "SHAKE256"
)

// DigestOutputLength returns the output length in bytes for a fixed-output algorithm.
func DigestOutputLength(algo DigestAlgorithm) (int, error) {
	switch algo {
	case AlgorithmSHA256, AlgorithmSHA3_256:
		return 32, nil
	case AlgorithmSHA384, AlgorithmSHA3_384:
		return 48, nil
	case AlgorithmSHA512, AlgorithmSHA3_512:
		return 64, nil
	}
	return 0, cerr.ErrAlgorithmNotPermitted
}

// newHasher returns a hash.Hash for the given algorithm.
func newHasher(algo DigestAlgorithm) (interface{ Write([]byte) (int, error); Sum([]byte) []byte }, error) {
	switch algo {
	case AlgorithmSHA256:
		return sha256.New(), nil
	case AlgorithmSHA384:
		return sha512.New384(), nil
	case AlgorithmSHA512:
		return sha512.New(), nil
	case AlgorithmSHA3_256:
		return sha3.New256(), nil
	case AlgorithmSHA3_384:
		return sha3.New384(), nil
	case AlgorithmSHA3_512:
		return sha3.New512(), nil
	case AlgorithmSHAKE128, AlgorithmSHAKE256:
		return nil, cerr.ErrAlgorithmNotPermitted
	}
	return nil, cerr.ErrAlgorithmNotPermitted
}

// Digest computes the hash digest of data using the specified algorithm.
// Family 1: digest(data []byte, algorithm string) ([]byte, error)
func Digest(data []byte, algorithm string) ([]byte, error) {
	algo := DigestAlgorithm(algorithm)

	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	if algo == AlgorithmSHAKE128 || algo == AlgorithmSHAKE256 {
		return nil, cerr.ErrAlgorithmNotPermitted
	}

	h, err := newHasher(algo)
	if err != nil {
		return nil, err
	}

	h.Write(data)
	return h.Sum(nil), nil
}

// DigestXOF computes the extendable-output hash (SHAKE) of data with variable output length.
// Family 2: digest_xof(data []byte, algorithm string, output_length uint32) ([]byte, error)
func DigestXOF(data []byte, algorithm string, outputLength uint32) ([]byte, error) {
	algo := DigestAlgorithm(algorithm)

	if err := config.AlgorithmPermitted(algorithm); err != nil {
		return nil, err
	}

	var shake sha3.ShakeHash
	switch algo {
	case AlgorithmSHAKE128:
		shake = sha3.NewShake128()
	case AlgorithmSHAKE256:
		shake = sha3.NewShake256()
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}

	if outputLength < 16 || outputLength > 512 {
		return nil, cerr.ErrInputTooLarge
	}

	shake.Write(data)
	output := make([]byte, outputLength)
	_, err := shake.Read(output)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// DigestAlgorithmInfo holds metadata about a digest algorithm.
type DigestAlgorithmInfo struct {
	Name         string
	OutputLength int
	Standard     string
	Mode         []string
}

// GetDigestAlgorithmInfo returns metadata for the given algorithm.
func GetDigestAlgorithmInfo(algorithm string) (*DigestAlgorithmInfo, error) {
	algo := DigestAlgorithm(algorithm)
	info := &DigestAlgorithmInfo{Name: algorithm}

	switch algo {
	case AlgorithmSHA256:
		info.OutputLength = 32
		info.Standard = "FIPS 180-4"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHA384:
		info.OutputLength = 48
		info.Standard = "FIPS 180-4"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHA512:
		info.OutputLength = 64
		info.Standard = "FIPS 180-4"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHA3_256:
		info.OutputLength = 32
		info.Standard = "FIPS 202"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHA3_384:
		info.OutputLength = 48
		info.Standard = "FIPS 202"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHA3_512:
		info.OutputLength = 64
		info.Standard = "FIPS 202"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHAKE128:
		info.OutputLength = -1
		info.Standard = "FIPS 202"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	case AlgorithmSHAKE256:
		info.OutputLength = -1
		info.Standard = "FIPS 202"
		info.Mode = []string{"FIPS", "GENERAL", "PQC"}
	default:
		return nil, cerr.ErrAlgorithmNotPermitted
	}

	return info, nil
}

// ListSupportedDigests returns all supported digest algorithms.
func ListSupportedDigests() []string {
	return []string{
		"SHA-256", "SHA-384", "SHA-512",
		"SHA3-256", "SHA3-384", "SHA3-512",
		"SHAKE128", "SHAKE256",
	}
}

// ConstantTimeCompare compares two byte slices in constant time.
func ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

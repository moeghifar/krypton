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

import "crypto/sha256"

// checksumSize is the number of checksum bytes appended during checked
// encoding, matching the Base58Check convention.
const checksumSize = 4

// DoubleSHA256 computes SHA256(SHA256(input)) and returns the full 32-byte
// digest. This is the default hash function used by [New] for checked
// encoding/decoding, matching the Base58Check convention.
func DoubleSHA256(input []byte) []byte {
	first := sha256.Sum256(input)
	second := sha256.Sum256(first[:])
	return second[:]
}

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

package mac

import (
	"crypto/cipher"
	"errors"
)

// cmac implements AES-CMAC per NIST SP 800-38B.
type cmac struct {
	block     cipher.Block
	k1        []byte
	k2        []byte
	buffer    []byte
	blockSize int
}

// NewCMAC creates a new AES-CMAC instance using the given AES cipher block.
func NewCMAC(block cipher.Block) (*cmac, error) {
	if block == nil {
		return nil, errors.New("mac: nil cipher block")
	}
	bs := block.BlockSize()
	c := &cmac{
		block:     block,
		k1:        make([]byte, bs),
		k2:        make([]byte, bs),
		buffer:    make([]byte, 0, bs),
		blockSize: bs,
	}
	c.generateSubkeys()
	return c, nil
}

func (c *cmac) generateSubkeys() {
	// L = E_K(0^b)
	l := make([]byte, c.blockSize)
	c.block.Encrypt(l, l)

	// K1 = L · x in GF(2^128)
	for i := 0; i < c.blockSize; i++ {
		c.k1[i] = l[i] << 1
		if i+1 < c.blockSize && l[i+1]&0x80 != 0 {
			c.k1[i] |= 0x01
		}
	}
	if l[0]&0x80 != 0 {
		c.k1[c.blockSize-1] ^= 0x87
	}

	// K2 = K1 · x in GF(2^128)
	for i := 0; i < c.blockSize; i++ {
		c.k2[i] = c.k1[i] << 1
		if i+1 < c.blockSize && c.k1[i+1]&0x80 != 0 {
			c.k2[i] |= 0x01
		}
	}
	if c.k1[0]&0x80 != 0 {
		c.k2[c.blockSize-1] ^= 0x87
	}
}

// Write adds data to the MAC computation.
func (c *cmac) Write(p []byte) (int, error) {
	c.buffer = append(c.buffer, p...)
	return len(p), nil
}

// Sum computes and returns the CMAC tag.
func (c *cmac) Sum(b []byte) []byte {
	bs := c.blockSize
	data := c.buffer

	var tag []byte
	if len(data) >= bs && len(data)%bs == 0 {
		// Complete last block: XOR with K1
		lastBlock := make([]byte, bs)
		copy(lastBlock, data[len(data)-bs:])
		for i := range lastBlock {
			lastBlock[i] ^= c.k1[i]
		}
		tag = c.encryptBlocks(data[:len(data)-bs], lastBlock)
	} else if len(data) >= bs {
		// Partial last block: pad with 10...0 and XOR with K2
		fullBlocks := (len(data) / bs) * bs
		lastBlock := make([]byte, bs)
		copy(lastBlock, data[fullBlocks:])
		lastBlock[len(data)-fullBlocks] = 0x80
		for i := range lastBlock {
			lastBlock[i] ^= c.k2[i]
		}
		tag = c.encryptBlocks(data[:fullBlocks], lastBlock)
	} else {
		// Pad with 10...0 and XOR with K2
		padded := make([]byte, bs)
		copy(padded, data)
		padded[len(data)] = 0x80
		for i := range padded {
			padded[i] ^= c.k2[i]
		}
		tag = c.encryptBlocks(nil, padded)
	}

	c.buffer = c.buffer[:0]
	return append(b, tag...)
}

func (c *cmac) encryptBlocks(prefix, lastBlock []byte) []byte {
	bs := c.blockSize
	x := make([]byte, bs) // running XOR state

	// Process all complete blocks except the last
	for i := 0; i < len(prefix); i += bs {
		for j := 0; j < bs; j++ {
			x[j] ^= prefix[i+j]
		}
		c.block.Encrypt(x, x)
	}

	// XOR last block and encrypt
	for j := 0; j < bs; j++ {
		x[j] ^= lastBlock[j]
	}
	c.block.Encrypt(x, x)
	return x
}

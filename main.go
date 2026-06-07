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

// krypton — A comprehensive cryptographic library CLI.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/moeghifar/krypton/pkg/cipher"
	"github.com/moeghifar/krypton/lib/config"
	"github.com/moeghifar/krypton/lib/drbg"
	"github.com/moeghifar/krypton/pkg/hash"
	"github.com/moeghifar/krypton/pkg/mac"
)

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	command := strings.ToLower(os.Args[1])

	if err := config.Init(config.ModeStandard, false); err != nil {
		fmt.Fprintf(os.Stderr, "config init failed: %v\n", err)
		os.Exit(1)
	}
	if err := drbg.InitGlobalDRBG(); err != nil {
		fmt.Fprintf(os.Stderr, "drbg init failed: %v\n", err)
		os.Exit(1)
	}

	switch command {
	case "digest":
		digestCmd(os.Args[2:])
	case "mac":
		macCmd(os.Args[2:])
	case "encrypt":
		encryptCmd(os.Args[2:])
	case "decrypt":
		fmt.Println("decrypt: use the library API directly for envelope-based decryption")
	case "help", "-h", "--help":
		help()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", command)
		help()
		os.Exit(1)
	}
}

func help() {
	fmt.Println(`krypton — Cryptographic library CLI

Usage: krypton <command> [arguments]

Commands:
  digest   <algorithm> <data>                    Compute hash digest
  mac      <algorithm> <key-hex> <data>          Compute MAC tag
  encrypt  <algorithm> <key-hex> <plaintext> [<context>]  Encrypt data
  help                                           Show this help

Examples:
  krypton digest SHA-256 "hello world"
  krypton mac HMAC-SHA256 "7365637265742d6b6579" "hello world"
  krypton encrypt AES-256-GCM "000102030405060708090a0b0c0d0e0f" "hello" "ctx"`)
}

func digestCmd(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: krypton digest <algorithm> <data>")
		os.Exit(1)
	}
	result, err := hash.Digest([]byte(args[1]), args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(result))
}

func macCmd(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: krypton mac <algorithm> <key-hex> <data>")
		os.Exit(1)
	}
	key, err := hex.DecodeString(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid key hex: %v\n", err)
		os.Exit(1)
	}
	tag, err := mac.Mac(key, []byte(args[2]), args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "mac failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(tag))
}

func encryptCmd(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: krypton encrypt <algorithm> <key-hex> <plaintext> [<context>]")
		os.Exit(1)
	}
	key, err := hex.DecodeString(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid key hex: %v\n", err)
		os.Exit(1)
	}
	ctx := ""
	if len(args) > 3 {
		ctx = args[3]
	}
	env, err := cipher.Encrypt(key, []byte(args[2]), ctx, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("nonce:      %s\n", env.Nonce)
	fmt.Printf("ciphertext: %s\n", env.Ciphertext)
	fmt.Printf("tag:        %s\n", env.Tag)
}

package hdwallet

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type Seed struct {
	Bytes []byte
}

func GenerateRootSeed(_mnemonic []string, passphrase string) *Seed {
	mnemonic := strings.Join(_mnemonic, " ")
	binarySeed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
	rootSeed := Seed{binarySeed}

	return &rootSeed
}

// ToHex returns the seed bytes as a hex encoded string
func (s *Seed) ToHex() string {
	src := s.Bytes
	seedHex := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(seedHex, s.Bytes)
	return string(seedHex)
}

func (s *Seed) String() string {
	return s.ToHex()
}

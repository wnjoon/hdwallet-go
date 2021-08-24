/*
 * [Descrption]
 * This file creates entropy(random numbers) to generate Mnemonic word according to BIP39 type
 */
package hdwallet

import (
	"crypto/rand"
	"errors"
	"log"
)

var entropyBitList = map[string]int{
	// Type : entrophyBits
	"BIP39_128": 128,
	"BIP39_160": 160,
	"BIP39_192": 192,
	"BIP39_224": 224,
	"BIP39_256": 256,
}

/*
 * GetEntropy
 */
func GetEntropy(mnemonicType string) ([]byte, error) {

	bitLength, exists := entropyBitList[mnemonicType]

	if !exists {
		log.Fatalf("%s is not supported mnemonic type", mnemonicType)
	}

	if bitLength < 128 || bitLength > 256 || bitLength%32 > 0 {
		return nil, errors.New("entropy length must be between 128 and 256 inclusive, and be divisible by 32")
	}

	entropyBytes := make([]byte, bitLength/8)
	_, err := rand.Read(entropyBytes)
	if err != nil {
		return nil, err
	}
	return entropyBytes, nil
}

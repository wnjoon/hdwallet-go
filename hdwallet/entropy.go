package hdwallet

import (
	"crypto/rand"
	"crypto/sha256"
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
 * private | 엔트로피 생성(Bytes)
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

// CheckSummed returns a bit slice of entropy with an appended check sum
func CheckSummed(ent []byte) []byte {
	cs := CheckSum(ent)
	bits := bytesToBits(ent)
	return append(bits, cs...)
}

// CheckSum returns a slice of bits from the given entropy
func CheckSum(ent []byte) []byte {
	h := sha256.New()
	h.Write(ent)
	cs := h.Sum(nil)
	hashBits := bytesToBits(cs)
	num := len(ent) * 8 / 32
	return hashBits[:num]
}

func bytesToBits(bytes []byte) []byte {
	length := len(bytes)
	bits := make([]byte, length*8)
	for i := 0; i < length; i++ {
		b := bytes[i]
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint8(j))
			bit := b & mask
			if bit == 0 {
				bits[(i*8)+8-(j+1)] = '0'
			} else {
				bits[(i*8)+8-(j+1)] = '1'
			}
		}
	}
	return bits
}

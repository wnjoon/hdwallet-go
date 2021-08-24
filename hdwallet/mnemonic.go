/*
 * [Descrption]
 * This file creates Mnemonic word according to BIP39 type
 * https://github.com/brianium/mnemonic/tree/master
 * https://iancoleman.io/bip39/#english
 */
package hdwallet

import (
	"crypto/sha256"
	"fmt"
	"strconv"
)

/*
 * GenerateMnemonicWord
 */
func GenerateMnemonicWord(ent []byte, mnemonicType string) ([]string, error) {

	const chunkSize = 11
	bits := checkSummed(ent)

	length := len(bits)
	words := make([]string, length/11)
	for i := 0; i < length; i += chunkSize {
		stringVal := string(bits[i : chunkSize+i])
		wordIndex, err := strconv.ParseInt(stringVal, 2, 64)
		if err != nil {
			return nil, fmt.Errorf("could not convert %s to word index", stringVal)
		}
		word := Mnemonic_wordlist_english[wordIndex]
		if err != nil {
			return nil, err
		}
		words[(chunkSize+i)/11-1] = word
	}
	return words, nil
}

// CheckSummed returns a bit slice of entropy with an appended check sum
func checkSummed(ent []byte) []byte {
	cs := checkSum(ent)
	bits := bytesToBits(ent)
	return append(bits, cs...)
}

// CheckSum returns a slice of bits from the given entropy
func checkSum(ent []byte) []byte {
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

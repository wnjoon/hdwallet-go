package hdwallet

// https://github.com/brianium/mnemonic/tree/master
// Tester : https://iancoleman.io/bip39/#english

import (
	"fmt"
	"strconv"
)

func GenerateMnemonicWord(ent []byte, mnemonicType string) ([]string, error) {

	const chunkSize = 11
	bits := CheckSummed(ent)

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

package hdwallet

// https://github.com/brianium/mnemonic/tree/master
// Tester : https://iancoleman.io/bip39/#english

import (
	"fmt"
	"strconv"
	"strings"
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
			return nil, fmt.Errorf("Could not convert %s to word index", stringVal)
		}
		word := Mnemonic_wordlist_english[wordIndex]
		if err != nil {
			return nil, err
		}
		words[(chunkSize+i)/11-1] = word
	}
	return words, nil
}

func getMnemonicString(strArray []string) string {
	return strings.Join(strArray, " ")
}

/*
 * Public
 * convertEntrophyToMnemonic
 * return: Mnemonic words
 * https://github.com/brianium/mnemonic/tree/master
 */
// func convertEntrophyToMnemonic(entrophy []byte) string {

// 	entrophyBits := len(entrophy) * 8

// 	// Get SHA256 Entrophy
// 	hash := sha256.New()
// 	hash.Write(entrophy)
// 	hashEnt := []byte(base64.URLEncoding.EncodeToString(hash.Sum(nil))) //

// 	// Checksum
// 	csBits := entrophyBits / 32
// 	cs := hashEnt[0]
// 	cs &= (byte)(0xFF << (8 - csBits))

// 	// Combine entrophy + checksum
// 	entcs := make([]byte, len(entrophy)+1)
// 	copy(entcs, entrophy)
// 	entcs[len(entcs)-1] = cs

// 	// Split entrophy + checksum into groups of 11 bits (0 ~ 2047)
// 	bits := ""
// 	for i := 0; i < len(entcs); i++ {
// 		bits += fmt.Sprintf("%08b", entcs[i])
// 	}

// 	// fmt.Println("bits:", bits)

// 	result := ""
// 	bitCount := entrophyBits + csBits
// 	for i := 0; i < bitCount; i += 11 {
// 		wordIndex, err := strconv.ParseInt(bits[i:i+11], 2, 64)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		// fmt.Println("wordIndex:", wordIndex)
// 		mnemonicWord := Mnemonic_wordlist_english[wordIndex]
// 		result += mnemonicWord + " "
// 	}
// 	return strings.Trim(result, " ")
// }

// func Generate(mnemonicType string, password string) {
// 	entropy, _ := GetEntropy(mnemonicType)
// 	mnemonicWord := convertEntrophyToMnemonic(entropy)

// 	fmt.Println(entropy, " ", mnemonicWord)
// }

// 	salt := []byte(strings.ToValidUTF8("mnemonic"+password, ""))

// 	binarySeed := pbkdf2.Key([]byte(mnemonicWord), salt, 2048, 64, sha512.New)

// 	fmt.Println(mnemonicWord)
// 	fmt.Println(hex.EncodeToString(binarySeed))

// 	hmac512 := hmac.New(sha512.New, secret)
// 	hmac512.Write(binarySeed)

// 	//masterKey := hmac512.Sum(nil)

// 	//secretKey := masterKey[:len(masterKey)/2]
// 	//chainCode := masterKey[len(masterKey)/2:]

// 	//privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	//publicKey := privateKey.PublicKey

// 	//fmt.Println(privateKey, " ", publicKey)
// 	// secretKeyBits := ""
// 	// for i := 0; i < len(secretKey); i++ {
// 	// 	secretKeyBits += fmt.Sprintf("%08b", secretKey[i])
// 	// }

// }

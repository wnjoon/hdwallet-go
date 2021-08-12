package hdwallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
)

// https://github.com/modood/btckeygen

var secret string = "bitcoin seed"

func GenerateMasterRootKey(rootSeed []byte) string {
	hmac512 := hmac.New(sha512.New, []byte(secret))
	hmac512.Write(rootSeed)
	masterRootKey := hmac512.Sum(nil)

	return hex.EncodeToString(masterRootKey)
}

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

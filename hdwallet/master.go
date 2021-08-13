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

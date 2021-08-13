package main

import (
	"fmt"

	"github.com/tyler-smith/go-bip32"
	"github.com/wnjoon/hdwallet-go/hdwallet"
	"github.com/wnjoon/hdwallet-go/utils"
)

func main() {
	mnemonicWord, err := hdwallet.GenerateMnemonicWord("BIP39_128")
	utils.HandleError(err)

	fmt.Println("mnemonicWord : ", mnemonicWord)

	rootSeed := hdwallet.GenerateRootSeed(mnemonicWord, "")
	fmt.Println("rootSeed : ", rootSeed)

	masterKey, _ := bip32.NewMasterKey(rootSeed.Bytes)
	publicKey := masterKey.PublicKey()
	fmt.Println("masterKey : ", masterKey)
	fmt.Println("publicKey : ", publicKey)

	ck0, _ := masterKey.NewChildKey(0)
	fmt.Println("Child0PrivateKey : ", ck0)
	fmt.Println("Child0PublicKey : ", ck0.PublicKey())
}

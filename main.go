package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip32"
	"github.com/wnjoon/hdwallet-go/hdwallet"
	"github.com/wnjoon/hdwallet-go/utils"
)

func main() {

	bipType := "BIP39_128"
	passphrase := ""

	ent, err := hdwallet.GetEntropy(bipType)
	utils.HandleError(err)
	fmt.Println("- entropy : ", hex.EncodeToString(ent))

	mnemonicWord, err := hdwallet.GenerateMnemonicWord(ent, bipType)
	utils.HandleError(err)
	fmt.Println("- mnemonicWord : ", mnemonicWord)

	rootSeed := hdwallet.GenerateRootSeed(mnemonicWord, passphrase)
	fmt.Println("- rootSeed : ", rootSeed)
	fmt.Println()

	masterKey, _ := bip32.NewMasterKey(rootSeed.Bytes)
	publicKey := masterKey.PublicKey()
	fmt.Println("- masterKey : ", masterKey)
	fmt.Println("- publicKey : ", publicKey)
	fmt.Println()

	ck0, _ := masterKey.NewChildKey(0)
	fmt.Println("- Child0PrivateKey : ", ck0)
	fmt.Println("- Child0PublicKey : ", ck0.PublicKey())
	fmt.Println()
}

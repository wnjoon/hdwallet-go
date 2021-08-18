package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"

	"github.com/wnjoon/hdwallet-go/hdwallet"
)

func main() {

	runTest()
}

func runTest() {
	bipType := "BIP39_128"
	passphrase := ""

	/*
	 * 1. Generate Entropy
	 */
	entropy, _ := hdwallet.GetEntropy(bipType)
	fmt.Println("- entropy(hex) : ", hex.EncodeToString(entropy))
	// entropy, _ := hex.DecodeString("f28544cc2886c2ec2595d14c5b441329")
	// fmt.Println("- entropy(hex) : ", entropy)

	/*
	 * 2. Generate Mnemonic Code
	 */
	mnemonicCode, err := hdwallet.GenerateMnemonicWord(entropy, bipType)
	hdwallet.HandleError(err)
	fmt.Println("- mnemonicCode : ", mnemonicCode)

	/*
	 * 3. Generate Binary(Root) Seed
	 */
	rootSeed := hdwallet.GenerateRootSeed(mnemonicCode, passphrase)
	fmt.Println("- rootSeed : ", rootSeed)

	/*
	 * 4. Generate Master(Private) Key
	 */
	privateKey, _ := hdwallet.GenerateKey(elliptic.P256(), rootSeed.Bytes)
	fmt.Println("- privateKey(Hex) : ", hex.EncodeToString(privateKey.D.Bytes()))

	/*
	 * 5. Generate Public Key
	 */
	publicKey_x := privateKey.PublicKey.X
	publicKey_y := privateKey.PublicKey.Y

	if elliptic.P256().IsOnCurve(publicKey_x, publicKey_y) {
		publicKey := elliptic.Marshal(elliptic.P256(), publicKey_x, publicKey_y)
		fmt.Println("- publicKey : ", hex.EncodeToString(publicKey[:]))
	}
}

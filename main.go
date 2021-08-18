package main

import (
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
	 * 4. Generate Master Key : Private
	 */
	masterKey, _ := hdwallet.GenerateMasterKey(rootSeed.Bytes)
	fmt.Println("- Master : Private : ", hex.EncodeToString(masterKey.Key))

	/*
	 * 5. Generate Master Key : Public
	 */
	publicKey := hdwallet.GetPublicKeyForPrivateKey(masterKey)
	fmt.Println("- Master : Public : ", hex.EncodeToString(publicKey))
	// publicKey := privateKey.GeneratePublicKey()
	// fmt.Println("- publicKey : ", hex.EncodeToString(publicKey.Key))

	/*
	 * 6. Generate Child Key : Private
	 */
	child0, _ := masterKey.GenerateChildKey(0)
	fmt.Println("- Child0 : Private : ", hex.EncodeToString(child0.Key))
	fmt.Println("- Child0 : IsPrivate : ", child0.IsPrivate)

	child0_pub := hdwallet.GetPublicKeyForPrivateKey(child0)
	fmt.Println("- Child0_pub : Public : ", hex.EncodeToString(child0_pub))
	// child0_public := child0.GeneratePublicKey()
	// fmt.Println("- Child0 : Public : ", hex.EncodeToString(child0_public.Key), " ", child0.IsPrivate)
}

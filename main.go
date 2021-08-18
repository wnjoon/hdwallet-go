package main

import (
	"encoding/hex"
	"fmt"

	"github.com/wnjoon/hdwallet-go/hdwallet"
)

func main() {
	GenerateKey()
}

func GenerateKey() {

	bipType := "BIP39_128"
	passphrase := ""

	/*
	 * 1. Generate Entropy
	 */
	entropy, _ := hdwallet.GetEntropy(bipType)
	fmt.Println("- entropy(hex) : ", hex.EncodeToString(entropy))

	/*
	 * 2. Generate Mnemonic Code
	 */
	mnemonicCode, _ := hdwallet.GenerateMnemonicWord(entropy, bipType)
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

	/*
	 * 6. Generate Child Key : Private
	 */
	child0, _ := masterKey.GenerateChildKey(0)
	fmt.Println("- Child0 : Private : ", hex.EncodeToString(child0.Key))

	child0_pub := hdwallet.GetPublicKeyForPrivateKey(child0)
	fmt.Println("- Child0 : Public : ", hex.EncodeToString(child0_pub))
}

// http://cryptostudy.xyz/crypto/article/9-HD-키-생성
// https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

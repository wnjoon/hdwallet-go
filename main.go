package main

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/tyler-smith/go-bip32"
	"github.com/wnjoon/hdwallet-go/hdwallet"

	"github.com/jbenet/go-base58"
)

func main() {

	testOriginal()
	// testBIPtoECDSA()

}

func testOriginal() {
	bipType := "BIP39_128"
	passphrase := ""

	// ent, err := hdwallet.GetEntropy(bipType)
	ent, err := hex.DecodeString("f28544cc2886c2ec2595d14c5b441329")

	hdwallet.HandleError(err)
	fmt.Println("- entropy(hex) : ", hex.EncodeToString(ent))

	mnemonicWord, err := hdwallet.GenerateMnemonicWord(ent, bipType)
	hdwallet.HandleError(err)
	fmt.Println("- mnemonicWord : ", mnemonicWord)

	rootSeed := hdwallet.GenerateRootSeed(mnemonicWord, passphrase)
	fmt.Println("- rootSeed : ", rootSeed)
	fmt.Println()

	privateKey, _ := hdwallet.GenerateKey(elliptic.P256(), rootSeed.Bytes)
	fmt.Println("- privateKey.Bytes : ", hex.EncodeToString(privateKey.D.Bytes()))
	fmt.Println("")

	if elliptic.P256().IsOnCurve(privateKey.PublicKey.X, privateKey.PublicKey.Y) {
		fmt.Println("	- publicKey.X : ", privateKey.PublicKey.X.String())
		fmt.Println("	- publicKey.Y : ", privateKey.PublicKey.Y.String())
		concatPubXY := privateKey.PublicKey.Y.String() + privateKey.PublicKey.X.String()
		fmt.Println("	- publicKey.X + publicKey.Y : ", concatPubXY)
		publicKeyXY, _ := new(big.Int).SetString(concatPubXY, 10)
		fmt.Println("- publicKey.XY.Bytes : ", hex.EncodeToString(publicKeyXY.Bytes()))

	}
}

func testBIPtoECDSA() {

	seed, err := bip32.NewSeed()
	if err != nil {
		log.Fatal(err)
	}

	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	decoded := base58.Decode(master.B58Serialize())
	privateKey := decoded[46:78]
	// fmt.Println(hexutil.Encode(privateKey))     // 0x801f14cc6b5f2b0785916685c838c8e64f7f4529a9ca7507c90e5f9078cefc07
	fmt.Println(hex.EncodeToString(privateKey)) // 0x801f14cc6b5f2b0785916685c838c8e64f7f4529a9ca7507c90e5f9078cefc07

	pubDecoded := base58.Decode(master.PublicKey().B58Serialize())
	publicKey := pubDecoded[45:78]
	fmt.Println(hex.EncodeToString(publicKey)) // 0x801f14cc6b5f2b0785916685c838c8e64f7f4529a9ca7507c90e5f9078cefc07

	// m/44'
	// key, err := master.NewChildKey(2147483648 + 44)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// decoded := base58.Decode(key.B58Serialize())
	// privateKey := decoded[46:78]
	// fmt.Println(hexutil.Encode(privateKey)) // 0x801f14cc6b5f2b0785916685c838c8e64f7f4529a9ca7507c90e5f9078cefc07

	// // Hex private key to ECDSA private key
	// privateKeyECDSA, err := crypto.ToECDSA(privateKey)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // ECDSA private key to hex private key
	// privateKey = crypto.FromECDSA(privateKeyECDSA)
	// fmt.Println(hexutil.Encode(privateKey)) // 0x801f14cc6b5f2b0785916685c838c8e64f7f4529a9ca7507c90e5f9078cefc07
}

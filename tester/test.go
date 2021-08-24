package tester

import (
	"fmt"

	"github.com/wnjoon/hdwallet-go/hdwallet"
)

const (
	bipType    = "BIP39_128"
	passphrase = ""
)

func GenerateRootKey() *hdwallet.Key {

	// 1. Entropy
	entropy, _ := hdwallet.GetEntropy(bipType)
	// 2. Mnemonic code
	mnemonicCode, _ := hdwallet.GenerateMnemonicWord(entropy, bipType)
	// 3. Root Seed
	rootSeed := hdwallet.GenerateRootSeed(mnemonicCode, passphrase)
	// 4. Generate Root Private Key
	rootKey, _ := hdwallet.CreateRootKey(rootSeed.Bytes)

	PrintEnvInfo(entropy, mnemonicCode, rootSeed.Bytes)
	PrintKeyInfo(rootKey)

	return rootKey
}

func GenerateChildKey(key *hdwallet.Key, childIdx uint32) *hdwallet.Key {
	childKey, _ := hdwallet.CreateChildKeyFromPrivateKey(key.PrivateKey, key.PublicKey, key.ChainCode, key.Depth, childIdx)
	fmt.Printf("\n----- Child Key [%d] -----\n", childKey.Depth)
	PrintKeyInfo(childKey)

	return childKey
}

# hdwallet-go

## History
- 2021.08.12 : Init commit, Write entropy and mnemonic functions
- 2021.08.13 : Write code to generate key (first commit version)
- 2021.08.17 : Update code to show detail descriptions
- 2021.08.18 : Adjust secp256r1
- 2021.08.19 : Adjust child key generation
- 2021.08.24 : PEM file generation, PrivateKey/PublicKey struct type support

## Purpose
- Adjust ECDSA 'secp256r1' algorithm, also called P256, to generate HD wallet key
- Most of HD wallet key is generated with 'secp256k1' since bitcoin uses it
- Hyperledger Fabric and some blockchain platforms uses secp256r1 -> Test is needed!

## P256(secp256r1)
- To adjust secp256r1, I modified some codes from original. You can find it [key.go](https://github.com/wnjoon/hdwallet-go/blob/main/hdwallet/key.go)

## Sequence of generating HD Master Key
1. Generate Mnemonic code using entropy(random number)
2. Generate Binary seed(also called RootSeed) using Mnemonic code with checksum
3. Generate Master Key(also called RootKey) by binary seed hasing with HMAC-SHA512 
4. Front of Master Key (256 bits) is Private key and the other (256 bits) is chaincode, used to generate child key.
5. Child key is also generated from HMAC-SHA512 and 2 parts of values(private key and chaincode)

## References
- ['tyler-smith'](https://github.com/tyler-smith/go-bip32)


## Sample (Tester)
```go
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
```

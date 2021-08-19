# hdwallet-go

## Why I tried?
For adjust HD wallet in Hyperledger Fabric.  
(There was NO reference or sample)  
A signature algorithm for ECDSA in Hyperledger fabric is 'secp256r1', however, Almost HD wallet key signatures were 'secp256k1' including Bitcoin. Then I just have to test how HD wallet is generated and what should I do when I want to adjust HD wallet in Hyperledger Fabric.


## Sequence of generating HD Master Key
1. Generate Mnemonic code using entropy(random number)
2. Generate Binary seed(also called RootSeed) using Mnemonic code with checksum
3. Generate Master Key(also called RootKey) by binary seed hasing with HMAC-SHA512 
4. Front of Master Key (256 bits) is Private key and the other (256 bits) is chaincode, used to generate child key.
5. Child key is also generated from HMAC-SHA512 and 2 parts of values(private key and chaincode)

## How to develop
Entropy and Binary seed was developed for my own, however generating master key and child key were kind of difficult things when hashing with HMAC-SHA512. There was a few information about Secret(normally used 'bitcoin seed' for bitcoin), a parameter for hashing.  
Then I used open library from ['tyler-smith'](https://github.com/tyler-smith/go-bip32), who developed most of HD wallet functions already.  

## P256(secp256r1) - That's why I write this code!
This code is started from testing *'Is it possible to adjust HD wallet to Hyperledger Fabric, which uses secp256r1, not secp256k1 used in bitcoin system?'*.  
To adjust secp256r1, I modified some codes from original. You can find it [key.go](https://github.com/wnjoon/hdwallet-go/blob/main/hdwallet/key.go).  
From generate entropy to binary seed is same as bitcoin, but generate key is different because of curve values.  
First, Get the privateKeyBytes which is half of intermediary(64 bytes) and make it P256 usable with curve(elliptic.P256()) to get a private key.
And Get the public key using curves(x, y). Child Key has same mechanism(little bit different).


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

	fmt.Printf("\n\nEnvironments\n")
	PrintEnvInfo(entropy, mnemonicCode, rootSeed.Bytes)
	fmt.Printf("\n\nRoot Key\n")
	PrintKeyInfo(rootKey)

	return rootKey
}

func GenerateChildKey(key *hdwallet.Key, childIdx uint32) *hdwallet.Key {
	childKey, _ := hdwallet.CreateChildKeyFromPrivateKey(key.PrivateKey, key.PublicKey, key.ChainCode, key.Depth, childIdx)
	fmt.Printf("\n\nChild Key [%d]\n", childKey.Depth)
	PrintKeyInfo(childKey)

	return childKey
}
```

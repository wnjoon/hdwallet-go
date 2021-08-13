# hdwallet-go

## Why I tried?
For adjust HD wallet in Hyperledger Fabric.  
(There was NO reference or sample)  
A signature algorithm for ECDSA in Hyperledger fabric is 'secp256r1', however, Almost HD wallet key signatures were 'secp256k1' including Bitcoin. Then I just have to test how HD wallet is generated and what should I do when I want to adjust HD wallet in Hyperledger Fabric.


## Sequence of generating HD Master Key
1. Generate Mnemonic code using entropy(random number)
2. Generate Binary seed(also called RootSeed) using Mnemonic code with checksum
3. Generate Master Key(also called RootKey) by binary seed hasing with HMAC-SHA512 

## How to develop
Entropy and Binary seed was developed for my own, however generating master key has kind of difficult things when hashing with HMAC-SHA512. There was a few information about Secret(normally used 'bitcoin seed' for bitcoin), a parameter for hashing.  
Then I used open library from ['tyler-smith'](https://github.com/tyler-smith/go-bip32), who developed most of HD wallet functions already.  

## Sample
```go
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
```
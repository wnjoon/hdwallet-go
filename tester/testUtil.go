package tester

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/wnjoon/hdwallet-go/hdwallet"
)

type Env struct {
	Entropy  string
	Mnemonic []string
	RootSeed string
}

type JsonKey struct {
	PrivateKey  string
	PublicKey   string
	Xcurve      *big.Int
	Ycurve      *big.Int
	ChildNumber string
	FingerPrint string
	ChainCode   string
	Depth       byte
}

func PrintEnvInfo(ent []byte, mnemonic []string, seed []byte) {
	env := Env{}
	env.Entropy = hex.EncodeToString(ent)
	env.Mnemonic = mnemonic
	env.RootSeed = hex.EncodeToString(seed)

	jsonBytes, _ := json.Marshal(env)
	var out bytes.Buffer
	json.Indent(&out, jsonBytes, "", "  ")
	fmt.Printf("\n----- Environments -----\n")
	fmt.Println(out.String())
}

func PrintKeyInfo(key *hdwallet.Key) {
	jsonKey := JsonKey{}
	jsonKey.PrivateKey = hex.EncodeToString(key.PrivateKey)
	jsonKey.PublicKey = hex.EncodeToString(key.PublicKey)
	jsonKey.Xcurve = key.Xcurve
	jsonKey.Ycurve = key.Ycurve
	jsonKey.ChildNumber = hex.EncodeToString(key.ChildNumber)
	jsonKey.FingerPrint = hex.EncodeToString(key.FingerPrint)
	jsonKey.ChainCode = hex.EncodeToString(key.ChainCode)
	jsonKey.Depth = key.Depth

	jsonBytes, _ := json.Marshal(jsonKey)
	var out bytes.Buffer
	json.Indent(&out, jsonBytes, "", "  ")
	fmt.Printf("\n----- Key Info -----\n")
	fmt.Println(out.String())
}

/*
 * ReadParentInfo
 */
func ReadParentInfo(jsonString string) *JsonKey {
	var keyOjb = JsonKey{}
	err := json.Unmarshal([]byte(jsonString), &keyOjb)

	if err != nil {
		log.Fatal("Failed to unmarshal parent key")
	}
	return &keyOjb
}

/*
 * PEM utilities - getPemMemory
 * This function makes pem type STRING about generated key pair
 */
func getPemMemory(privateKeyValue []byte, xCurve *big.Int, yCurve *big.Int) (string, string) {
	priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priKey.D = new(big.Int).SetBytes(privateKeyValue)
	priKey.X = xCurve
	priKey.Y = yCurve

	x509Encoded, _ := x509.MarshalECPrivateKey(priKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	fmt.Println("PrivateKey : ", string(pemEncoded))
	fmt.Println("PublicKey : ", string(pemEncodedPub))

	return string(pemEncoded), string(pemEncodedPub)
}

/*
 * PEM utilities - getPemFile
 * This function makes pem FILE string about generated key pair
 */
func getPemFile(privateKeyValue []byte, xCurve *big.Int, yCurve *big.Int) (string, string) {

	priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priKey.D = new(big.Int).SetBytes(privateKeyValue)
	priKey.X = xCurve
	priKey.Y = yCurve

	publicKey := &priKey.PublicKey

	x509EncodedPrivateKey, _ := x509.MarshalECPrivateKey(priKey)
	x509EncodedPublicKey, _ := x509.MarshalPKIXPublicKey(publicKey)

	// Save to Pem file
	// Private
	pemPrivateFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPrivateBlock = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509EncodedPrivateKey,
	}

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPrivateFile.Close()
	// Public
	pemPublicFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var pemPublicBlock = &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: x509EncodedPublicKey,
	}

	err = pem.Encode(pemPublicFile, pemPublicBlock)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemPublicFile.Close()

	pemEncodedPrivateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509EncodedPrivateKey})
	pemEncodedPublicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPublicKey})
	return string(pemEncodedPrivateKey), string(pemEncodedPublicKey)
}

/*
 * PEM utilities - decodePEMContent
 * This function decodes PEM content to hex string for verification
 */
func decodePEMContent(pemEncodedPrivateKey string, pemEncodedPublicKeys string) {
	block, _ := pem.Decode([]byte(pemEncodedPrivateKey))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPublicKeys))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	fmt.Println("Decoded Private Key from PEM : ", hex.EncodeToString(privateKey.D.Bytes()))
	fmt.Println("Decoded Public Key from PEM : ", hex.EncodeToString(elliptic.Marshal(publicKey, publicKey.X, publicKey.Y)))
}

package tester

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/wnjoon/hdwallet-go/hdwallet"
)

type Env struct {
	Entropy  string
	Mnemonic []string
	RootSeed string
}

type JsonKey struct {
	//Version     []byte
	// IsPrivate   bool
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
	fmt.Println(out.String())
}

func ReadParentInfo(jsonString string) *JsonKey {
	var keyOjb = JsonKey{}
	err := json.Unmarshal([]byte(jsonString), &keyOjb)

	if err != nil {
		log.Fatal("Failed to unmarshal parent key")
	}
	return &keyOjb
}

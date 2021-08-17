package hdwallet

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"log"

	"github.com/FactomProject/basen"
	// "github.com/FactomProject/basen"
)

var (
	curve = elliptic.P256()
	// curve       = btcutil.Secp256k1()

	curveParams = curve.Params()

	// BitcoinBase58Encoding is the encoding used for bitcoin addresses
	BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
)

func HandleError(err error) {
	if err != nil {
		log.Panic("Error : ", err)
	}
}

func validatePrivateKey(key []byte) error {
	if fmt.Sprintf("%x", key) == "0000000000000000000000000000000000000000000000000000000000000000" || //if the key is zero
		bytes.Compare(key, curveParams.N.Bytes()) >= 0 || //or is outside of the curve
		len(key) != 32 { //or is too short
		return ErrInvalidPrivateKey
	}

	return nil
}

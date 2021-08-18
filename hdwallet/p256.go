package hdwallet

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

var one = new(big.Int).SetInt64(1)
var ErrShortBuffer = errors.New("short buffer")
var ErrUnexpectedEOF = errors.New("unexpected EOF")

// // PrivateKey represents an ECDSA private key.
// type PrivateKey struct {
// 	PublicKey
// 	D *big.Int
// }

// // PublicKey represents an ECDSA public key.
// type PublicKey struct {
// 	elliptic.Curve
// 	X, Y *big.Int
// }

func GenerateKey(c elliptic.Curve, seed []byte) (*PrivateKey, error) {
	k, err := randFieldElement(c, seed)
	if err != nil {
		return nil, err
	}

	// fmt.Println(len(k.Bytes()))

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// func randFieldElement(c elliptic.Curve, seed []byte) (k *big.Int, err error) {
// 	params := c.Params()
// 	b := make([]byte, params.BitSize/8+8)

// 	// if len(seed) < len(b) {
// 	// 	fmt.Println(len(seed), " ", len(b))
// 	// 	log.Fatal("len(seed) < len(b)")
// 	// }
// 	copy(b, seed)
// 	fmt.Println("b : ", len(b), " seed : ", len(seed))
// 	fmt.Println(b)

// 	k = new(big.Int).SetBytes(b)
// 	n := new(big.Int).Sub(params.N, one)
// 	k.Mod(k, n)
// 	k.Add(k, one)
// 	return
// }

package hdwallet

import (
	"crypto/elliptic"
	"errors"
	"log"
	"math/big"
)

var one = new(big.Int).SetInt64(1)
var ErrShortBuffer = errors.New("short buffer")
var ErrUnexpectedEOF = errors.New("unexpected EOF")

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func GenerateKey(c elliptic.Curve, seed []byte) (*PrivateKey, error) {
	k, err := randFieldElement(c, seed)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func randFieldElement(c elliptic.Curve, seed []byte) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	// _, err = io.ReadFull(seed, b)
	// if err != nil {
	// 	return
	// }

	if len(seed) < len(b) {
		log.Fatal("len(seed) < len(b)")
	}
	copy(b, seed)

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// func readAllSeeds(r []byte, buf []byte, min int) (n int, err error) {
// 	if len(buf) < min {
// 		return 0, ErrShortBuffer
// 	}
// 	for n < min && err == nil {
// 		var nn int
// 		nn, err = r.Read(buf[n:])
// 		n += nn
// 	}
// 	if n >= min {
// 		err = nil
// 	} else if n > 0 && err == EOF {
// 		err = ErrUnexpectedEOF
// 	}
// 	return
// }

// func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
// 	k, err := randFieldElement(c, rand)
// 	if err != nil {
// 		return nil, err
// 	}

// 	priv := new(PrivateKey)
// 	priv.PublicKey.Curve = c
// 	priv.D = k
// 	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
// 	return priv, nil
// }

// func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
// 	params := c.Params()
// 	b := make([]byte, params.BitSize/8+8)
// 	_, err = io.ReadFull(rand, b)
// 	if err != nil {
// 		return
// 	}

// 	k = new(big.Int).SetBytes(b)
// 	n := new(big.Int).Sub(params.N, one)
// 	k.Mod(k, n)
// 	k.Add(k, one)
// 	return
// }

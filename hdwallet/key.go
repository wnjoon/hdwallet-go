/*
 * [Descrption]
 * This file generate key pair using binary seed
 * Included Key : Root, Child
 */
package hdwallet

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"log"
	"math/big"
)

// Key represents a bip32 extended key
type Key struct {
	PrivateKey  []byte
	PublicKey   []byte
	Xcurve      *big.Int
	Ycurve      *big.Int
	ChildNumber []byte
	FingerPrint []byte
	ChainCode   []byte
	Depth       byte
}

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

/*
 * ========== Root Key ==========
 */
func CreateRootKey(seed []byte) (*Key, error) {

	// create root key and chaincode
	hmac := hmac.New(sha512.New, nil)
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	intermediary := hmac.Sum(nil) // length : 64

	// Split it into our key and chain code
	keyBytes := intermediary[:32]
	chainCode := intermediary[32:]

	// Validate key
	err = validatePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	_, privateKey, x, y, _ := getPrivateKey(elliptic.P256(), keyBytes)
	/*
	 * To get a STRUCT of Private key and Public Key
	 * (type PrivateKey struct) privateKey, _, _, _, _ := getPrivateKey(elliptic.P256(), keyBytes)
	 * (type PublicKey struct)	publicKey := privateKey.PublicKey
	 */

	publicKey := getPublicKey(x, y)

	// Create the key struct (To see Hex values)
	key := &Key{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Xcurve:      x,
		Ycurve:      y,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		ChainCode:   chainCode,
		Depth:       0x0,
	}
	return key, nil
}

// Generate Private Key
func getPrivateKey(c elliptic.Curve, privateKeyBytes []byte) (*PrivateKey, []byte, *big.Int, *big.Int, error) {
	k, err := randFieldElement(c, privateKeyBytes)
	if err != nil {
		return nil, nil, big.NewInt(0), big.NewInt(0), err
	}

	privateKey := k.Bytes()
	xCurve, yCurve := c.ScalarBaseMult(privateKey)

	// It construct Private Key struct (Optional but Important)
	privateKeyStruct := new(PrivateKey)
	privateKeyStruct.PublicKey.Curve = c
	privateKeyStruct.D = k
	privateKeyStruct.PublicKey.X = xCurve
	privateKeyStruct.PublicKey.Y = yCurve

	return privateKeyStruct, privateKey, xCurve, yCurve, nil
}

func getPublicKey(x *big.Int, y *big.Int) []byte {
	if !elliptic.P256().IsOnCurve(x, y) {
		log.Fatal("Error in IsOnCurve")
	}
	publicKey := elliptic.Marshal(elliptic.P256(), x, y)
	return publicKey
}

/*
 * ========== Child Key ==========
 */
// NewChildKey derives a child key from a given parent as outlined by bip32
func CreateChildKeyFromPrivateKey(parentPrikey []byte,
	parentPubkey []byte,
	cc []byte,
	depth byte,
	childIdx uint32) (*Key, error) {
	// Fail early if trying to create hardned child from public key

	intermediary, err := getIntermediaryFromPrikey(parentPrikey, cc, childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &Key{
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       depth + 1,
		// IsPrivate:   true,
	}

	// [TODO] Is it necessary?
	fingerprint, err := hash160(parentPubkey)
	if err != nil {
		return nil, err
	}
	childKey.FingerPrint = fingerprint[:4]
	_, childKey.PrivateKey, childKey.Xcurve, childKey.Ycurve, _ = getChildPrivateKey(intermediary[:32], parentPrikey)
	childKey.PublicKey = getPublicKey(childKey.Xcurve, childKey.Ycurve)

	// Validate key
	err = validatePrivateKey(childKey.PrivateKey)
	if err != nil {
		return nil, err
	}
	return childKey, nil
}

func getIntermediaryFromPrikey(key []byte, cc []byte, childIdx uint32) ([]byte, error) {
	// Get intermediary to create key and chaincode from Hardened children are based on the private key
	// NonHardened children are based on the public key
	childIndexBytes := uint32Bytes(childIdx)

	var data []byte
	if childIdx >= FirstHardenedChild {
		// [TODO] First Hardened Child?
		data = append([]byte{0x0}, key...)
	} else {
		data = key
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, cc)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

/*
 * Since child Key needs more parameters, function is seperated
 */
func getChildPrivateKey(chaincode []byte, parentPrivateKey []byte) (*PrivateKey, []byte, *big.Int, *big.Int, error) {
	var chaincodeInt big.Int
	var parentPrivateKeyInt big.Int
	chaincodeInt.SetBytes(chaincode)
	parentPrivateKeyInt.SetBytes(parentPrivateKey)

	chaincodeInt.Add(&chaincodeInt, &parentPrivateKeyInt)

	privateKeyStruct, privateKey, x, y, _ := getPrivateKey(elliptic.P256(), chaincodeInt.Bytes())

	return privateKeyStruct, privateKey, x, y, nil
}

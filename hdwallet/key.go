package hdwallet

// import (
// 	"crypto/elliptic"
// 	"crypto/hmac"
// 	"crypto/sha512"
// 	"log"
// 	"math/big"
// )

// // Key represents a bip32 extended key
// type HDKey struct {
// 	IsPrivate   *PrivateKey
// 	Key         []byte
// 	Version     []byte
// 	ChildNumber []byte
// 	FingerPrint []byte
// 	ChainCode   []byte
// 	Depth       byte
// 	// IsPrivate   bool
// }

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

// func GenerateMasterKey(seed []byte) (*HDKey, error) {

// 	// Generate key and chaincode
// 	hmac := hmac.New(sha512.New, nil)
// 	_, err := hmac.Write(seed)
// 	if err != nil {
// 		return nil, err
// 	}
// 	intermediary := hmac.Sum(nil) // length : 64

// 	// Split it into our key and chain code
// 	keyBytes := intermediary[:32]
// 	chainCode := intermediary[32:]

// 	// Validate key
// 	err = validatePrivateKey(keyBytes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	privateKey, _ := SetP256ToPrivateKey(elliptic.P256(), keyBytes)

// 	// Create the key struct
// 	key := &HDKey{
// 		Version:     PrivateWalletVersion,
// 		ChainCode:   chainCode,
// 		Key:         privateKey.D.Bytes(),
// 		Depth:       0x0,
// 		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
// 		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
// 		IsPrivate:   privateKey,
// 	}

// 	return key, nil
// }

// // GeneratePrivateKey (개인키 생성)
// func SetP256ToPrivateKey(c elliptic.Curve, privateKeyBytes []byte) (*PrivateKey, error) {
// 	k, err := randFieldElement(c, privateKeyBytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	priv := new(PrivateKey)
// 	priv.PublicKey.Curve = c
// 	priv.D = k
// 	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
// 	return priv, nil
// }

// func GetPublicKeyForPrivateKey(key *HDKey) []byte {
// 	return key.GeneratePublicKey().Key
// }

// // GeneratePrivateKey (공개키 생성)
// func (key *HDKey) GeneratePublicKey() *HDKey {
// 	privateKey := key.IsPrivate

// 	publicKey_x := privateKey.PublicKey.X
// 	publicKey_y := privateKey.PublicKey.Y

// 	if !elliptic.P256().IsOnCurve(publicKey_x, publicKey_y) {
// 		log.Fatal("Error in IsOnCurve")
// 	}
// 	publicKey := elliptic.Marshal(elliptic.P256(), publicKey_x, publicKey_y)

// 	return &HDKey{
// 		Version:     PublicWalletVersion,
// 		Key:         publicKey,
// 		Depth:       key.Depth,
// 		ChildNumber: key.ChildNumber,
// 		FingerPrint: key.FingerPrint,
// 		ChainCode:   key.ChainCode,
// 		IsPrivate:   nil,
// 	}
// }

// // NewChildKey derives a child key from a given parent as outlined by bip32
// func (key *HDKey) GenerateChildKey(childIdx uint32) (*HDKey, error) {
// 	// Fail early if trying to create hardned child from public key
// 	if key.IsPrivate == nil && childIdx >= FirstHardenedChild {
// 		return nil, ErrHardnedChildPublicKey
// 	}

// 	intermediary, err := key.getIntermediary(childIdx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create child Key with data common to all both scenarios
// 	childKey := &HDKey{
// 		ChildNumber: uint32Bytes(childIdx),
// 		ChainCode:   intermediary[32:],
// 		Depth:       key.Depth + 1,
// 		IsPrivate:   key.IsPrivate,
// 	}

// 	// Bip32 CKDpriv (Private Key)
// 	if key.IsPrivate != nil {
// 		childKey.Version = PrivateWalletVersion
// 		fingerprint, err := hash160(GetPublicKeyForPrivateKey(key))
// 		if err != nil {
// 			return nil, err
// 		}
// 		childKey.FingerPrint = fingerprint[:4]
// 		// childKey.Key = generateChildPrivateKey(intermediary[:32], key.Key)
// 		childKey.IsPrivate = generateChildPrivateKey(intermediary[:32], key.Key)
// 		childKey.Key = childKey.IsPrivate.D.Bytes()

// 		// Validate key
// 		err = validatePrivateKey(childKey.Key)
// 		if err != nil {
// 			return nil, err
// 		}
// 		// Bip32 CKDpub
// 	} else {
// 		// keyBytes := GetPublicKeyForPrivateKey(intermediary[:32])
// 		x, y := elliptic.P256().ScalarBaseMult(intermediary[:32])

// 		if !elliptic.P256().IsOnCurve(x, y) {
// 			log.Fatal("Error in IsOnCurve")
// 		}
// 		publicKey := elliptic.Marshal(elliptic.P256(), x, y)

// 		// Validate key
// 		// err := validateChildPublicKey(publicKey)
// 		// if err != nil {
// 		// 	return nil, err
// 		// }

// 		childKey.Version = PublicWalletVersion
// 		fingerprint, err := hash160(key.Key)
// 		if err != nil {
// 			return nil, err
// 		}
// 		childKey.FingerPrint = fingerprint[:4]
// 		// childKey.Key = addPublicKeys(keyBytes, key.Key)
// 		childKey.Key = publicKey
// 		childKey.IsPrivate = nil
// 	}
// 	return childKey, nil
// }

// func (key *HDKey) getIntermediary(childIdx uint32) ([]byte, error) {
// 	// Get intermediary to create key and chaincode from
// 	// Hardened children are based on the private key
// 	// NonHardened children are based on the public key
// 	childIndexBytes := uint32Bytes(childIdx)

// 	var data []byte
// 	if childIdx >= FirstHardenedChild {
// 		// [TODO] First Hardened Child?
// 		data = append([]byte{0x0}, key.Key...)
// 	} else {
// 		if key.IsPrivate == nil {
// 			data = GetPublicKeyForPrivateKey(key)
// 		} else {
// 			data = key.Key
// 		}
// 	}
// 	data = append(data, childIndexBytes...)

// 	hmac := hmac.New(sha512.New, key.ChainCode)
// 	_, err := hmac.Write(data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return hmac.Sum(nil), nil
// }

// func generateChildPrivateKey(chaincode []byte, parentPrivateKey []byte) *PrivateKey {
// 	var chaincodeInt big.Int
// 	var parentPrivateKeyInt big.Int
// 	chaincodeInt.SetBytes(chaincode)
// 	parentPrivateKeyInt.SetBytes(parentPrivateKey)

// 	chaincodeInt.Add(&chaincodeInt, &parentPrivateKeyInt)
// 	// key1Int.Mod(&key1Int, curve.Params().N)

// 	privateKey, _ := SetP256ToPrivateKey(elliptic.P256(), chaincodeInt.Bytes())

// 	return privateKey
// }

// // NewChildKey derives a child key from a given parent as outlined by bip32
// func GenerateChildKeyFromPrivateKey(prikey []byte, cc []byte, depth byte, childIdx uint32) (*HDKey, error) {
// 	// Fail early if trying to create hardned child from public key

// 	intermediary, err := getIntermediaryFromPrivateKey(prikey, cc, childIdx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Create child Key with data common to all both scenarios
// 	childKey := &HDKey{
// 		ChildNumber: uint32Bytes(childIdx),
// 		ChainCode:   intermediary[32:],
// 		Depth:       depth + 1,
// 		//IsPrivate:   key.IsPrivate,
// 	}

// 	// Bip32 CKDpriv (Private Key)
// 	childKey.Version = PrivateWalletVersion
// 	fingerprint, err := hash160(GetPublicKeyForPrivateKey(key))
// 	if err != nil {
// 		return nil, err
// 	}
// 	childKey.FingerPrint = fingerprint[:4]
// 	// childKey.Key = generateChildPrivateKey(intermediary[:32], key.Key)
// 	childKey.IsPrivate = generateChildPrivateKey(intermediary[:32], prikey)
// 	childKey.Key = childKey.IsPrivate.D.Bytes()

// 	// Validate key
// 	err = validatePrivateKey(childKey.Key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// Bip32 CKDpub

// 	return childKey, nil
// }

// func getIntermediaryFromPrivateKey(key []byte, cc []byte, childIdx uint32) ([]byte, error) {
// 	// Get intermediary to create key and chaincode from
// 	// Hardened children are based on the private key
// 	// NonHardened children are based on the public key
// 	childIndexBytes := uint32Bytes(childIdx)

// 	var data []byte
// 	if childIdx >= FirstHardenedChild {
// 		// [TODO] First Hardened Child?
// 		data = append([]byte{0x0}, key...)
// 	} else {
// 		data = key
// 	}
// 	data = append(data, childIndexBytes...)

// 	hmac := hmac.New(sha512.New, cc)
// 	_, err := hmac.Write(data)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return hmac.Sum(nil), nil
// }

// // GeneratePrivateKey (공개키 생성)
// func (key *HDKey) GeneratePublicKeyFromPrivateKey(x *big.Int, y *big.Int) *HDKey {
// 	if !elliptic.P256().IsOnCurve(x, y) {
// 		log.Fatal("Error in IsOnCurve")
// 	}
// 	publicKey := elliptic.Marshal(elliptic.P256(), x, y)

// 	return &HDKey{
// 		Version:     PublicWalletVersion,
// 		Key:         publicKey,
// 		Depth:       key.Depth,
// 		ChildNumber: key.ChildNumber,
// 		FingerPrint: key.FingerPrint,
// 		ChainCode:   key.ChainCode,
// 		IsPrivate:   nil,
// 	}
// }

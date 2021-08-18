package hdwallet

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/FactomProject/basen"
	"golang.org/x/crypto/ripemd160"
	// "github.com/FactomProject/basen"
)

const (
	// FirstHardenedChild is the index of the firxt "harded" child key as per the
	// bip32 spec
	FirstHardenedChild = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	curve = elliptic.P256()
	// curve       = btcutil.Secp256k1()

	curveParams = curve.Params()

	// BitcoinBase58Encoding is the encoding used for bitcoin addresses
	BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

	// PrivateWalletVersion is the version flag for serialized private keys
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicWalletVersion is the version flag for serialized private keys
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length
	ErrSerializedKeyWrongSize = errors.New("serialized keys should by exactly 82 bytes")

	// ErrHardnedChildPublicKey is returned when trying to create a harded child
	// of the public key
	ErrHardnedChildPublicKey = errors.New("can't create hardened child for public key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")
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

func randFieldElement(c elliptic.Curve, seed []byte) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)

	copy(b, seed)

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func hash160(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashRipeMD160(hash1)
	if err != nil {
		return nil, err
	}

	return hash2, nil
}

func hashSha256(data []byte) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hashRipeMD160(data []byte) ([]byte, error) {
	hasher := ripemd160.New()
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

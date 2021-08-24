package main

import "github.com/wnjoon/hdwallet-go/tester"

func main() {
	tester.GenerateRootKey()

	// // Test for making children
	// root := tester.GenerateRootKey()
	// tester.GenerateChildKey(root, 0)
	// child01 := tester.GenerateChildKey(root, 1)
	// tester.GenerateChildKey(child01, 0)

}

// http://cryptostudy.xyz/crypto/article/9-HD-키-생성
// https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

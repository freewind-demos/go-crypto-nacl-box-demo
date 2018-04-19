package main;

import (
	"crypto/rand"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"fmt"
)

func main() {
	myPublicKey, myPrivateKey, _ := box.GenerateKey(rand.Reader)
	fmt.Printf("My private key: %02X\n", myPrivateKey)
	fmt.Printf("My public key: %02X\n", myPublicKey)

	peerPublicKey, peerPrivateKey, _ := box.GenerateKey(rand.Reader)
	fmt.Printf("Peer private key: %02X\n", peerPrivateKey)
	fmt.Printf("Peer public key: %02X\n", peerPublicKey)

	sharedSecret := computeSharedSecret(peerPublicKey, myPrivateKey)
	fmt.Printf("Shared secret: %02X\n", sharedSecret)

	message := []byte{1, 2, 3, 4, 5}
	nonce := [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
	fmt.Printf("message : %02X\n", message)
	fmt.Printf("Nonce   : %02X\n", nonce)

	//output := []byte{10, 11}
	box1 := secretbox.Seal([]byte{}, message, &nonce, sharedSecret)
	fmt.Printf("Box1    : %02X\n", box1)

	opened, _ := secretbox.Open([]byte{}, box1, &nonce, sharedSecret)
	fmt.Printf("Opened  : %02X\n", opened)
}

func computeSharedSecret(peerPublicKey, privateKey *[32]byte) (sharedSecret *[32]byte) {
	sharedSecret = new([32]byte)
	box.Precompute(sharedSecret, peerPublicKey, privateKey)
	return
}

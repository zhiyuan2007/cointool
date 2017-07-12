package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/skycoin/skycoin/src/cipher"
)

func myrandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func main() {
	p, s := cipher.GenerateKeyPair()
	fmt.Printf("pub:%s\n", hex.EncodeToString(p[:]))
	fmt.Printf("sec:%s\n", hex.EncodeToString(s[:]))
	a := cipher.AddressFromPubKey(p)
	fmt.Printf("addr:%s\n", a.String())
	h := cipher.SumSHA256(myrandBytes(256))
	fmt.Printf("seed hash:%s\n", hex.EncodeToString(h[:]))
	sig := cipher.SignHash(h, s)
	fmt.Printf("sig:%s\n", sig.Hex())
	cipher.ChkSig(a, h, sig)
}

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

func verify_genenis_block() {
	p := "037a5d533722bce1e317605b45138bb9275741e9015a4e76d303ee6475282f336e"
	s := "b2c67fa55a88cdaa4d8d192a56c1322045d39a35b2811de9dca66fbbb651acd2"
	//sig := "2159d998d974777e5340750a462c6686167db18989f0c0b91ddf43f242e9dc035e90fb5e7e44ec074113c1a5d56159dced98adf535592262c77ee07177024a8801"
	sig := "9cdc1b2b9566ab78c6d656bfb34f4976c508286c35cd738142af12247ee5f07623854843568a0b02cdafcfd0b396682b99760845605c131557b212a1d3ec3d3001"
	addr := "WRV6X38t1jsbiRniPtotixv5g3wznjLDEm"
	h := "78aa723ac8151b72a0ec1dd873cd092f48d410f505d9567fb37b0ce7e8ed6d23"

	fmt.Println("start....")
	fmt.Println("start....")
	fmt.Println("start....")
	pb, e := cipher.PubKeyFromHex(p)
	if e != nil {
		fmt.Printf("pubkey form hex failed\n")
	}
	sb, e := cipher.SecKeyFromHex(s)
	if e != nil {
		fmt.Printf("seckey form hex failed\n")
	}
	addr1 := cipher.AddressFromPubKey(pb)
	addr2 := cipher.AddressFromSecKey(sb)
	hb, e := cipher.SHA256FromHex(h)
	if e != nil {
		fmt.Printf("sha256 from hex failed\n")
	}
	p1, e1 := cipher.PubKeyFromSig(cipher.MustSigFromHex(sig), hb)
	if e1 != nil {
		fmt.Printf("pubkey from sig hex failed: %+v\n", e1)
	}
	if p1.Hex() != p {
		fmt.Printf("pubkey from sig failed\n")
		fmt.Printf("pubkey----- %s\n", p)
		fmt.Printf("recover---- %s\n", p1.Hex())
	}

	sss := cipher.SignHash(hb, sb)
	err := cipher.ChkSig(addr1, hb, sss)
	if err != nil {
		fmt.Printf("check sig error\n")
	} else {
		fmt.Printf("sig is rrrrrrrrright\n")
		fmt.Printf("hb %s\n", h)
		fmt.Printf("sb %s\n", s)
		fmt.Printf("sig is %s\n", sss.Hex())

	}
	p2, e2 := cipher.PubKeyFromSig(sss, hb)
	if e2 != nil {
		fmt.Printf("pubkey from sig hex failed: %+v\n", e2)
	} else {
		fmt.Printf("pubkey from sig sss: %s\n", p2.Hex())
	}
	if p2.Hex() != p {
		fmt.Printf("pubkey from sig failed\n")
		fmt.Printf("pubkey----- %s\n", p)
		fmt.Printf("recover---- %s\n", p2.Hex())
	}

	if addr1.String() != addr {
		fmt.Printf("addr from pubkey failed\n")
	}
	if addr2.String() != addr {
		fmt.Printf("addr from seckey failed\n")
	}

}
func verify_sig() {
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
func main() {
	verify_genenis_block()
	//verify_sig()
}

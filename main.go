package main

import (
	"AdvancedVRF/vrf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	fmt.Println("===================ParamGen===================")
	pg := vrf.ParamGen("16-1024")
	fmt.Println("PG.N", pg.N)
	fmt.Println("PG.t", pg.T)
	fmt.Println("===================KeyGen===================")
	pk, sk, leaves := vrf.KeyGen()
	log.Println("pkv(Merkle Root):", hex.EncodeToString(pk[:]), "skv(r):", hex.EncodeToString(sk[:]))

	leavesHashArr := [1024]*[sha256.Size]byte{}
	for i, leave := range leaves {
		// Check two leaves have same parents
		leaveHash32 := [32]byte{}
		copy(leaveHash32[:], leave)
		leavesHashArr[i] = &leaveHash32
	}
	log.Println("PK", hex.EncodeToString(pk[:]))
	log.Println("===================sk.Eval===================")
	mu, _ := vrf.GenRandomBytes(32)
	muHex32 := [32]byte{}
	copy(muHex32[:], mu)
	i := 1021
	j := 10
	//v, pi(y,ap)
	log.Println("leaveHashes:", len(leavesHashArr))
	log.Println(leavesHashArr[1])
	vrfProof, ok, authPath := sk.Eval(muHex32, leavesHashArr[:], int32(i), int32(j))
	log.Println("Output VRF Hex Value", ok)
	log.Println("Output VRF Proof", hex.EncodeToString(vrfProof[:]))
	//get the path list1[6] 1023
	log.Println("===================pk.Verify===================")
	//𝑦 is 𝑥𝑖,0 in above sk.Eval
	//mu, i,j,v, y,ap
	output := pk.Verify(muHex32, leavesHashArr[:], int32(i), int32(j), vrfProof, authPath)
	log.Println("Verify result:", output)
}

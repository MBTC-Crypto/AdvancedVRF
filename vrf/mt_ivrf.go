package vrf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strconv"
	"strings"
)

// ParamGen to generate an implicit public parameter
func ParamGen(s string) (p *PublicParameter) {
	log.Println("Input s:", s)
	sArr := strings.Split(s, "-")
	t, _ := strconv.Atoi(sArr[0])
	N, _ := strconv.Atoi(sArr[1])
	newPP := PublicParameter{T: int32(t), N: int32(N)}
	return &newPP
}

// KeyGen to generate a public-secret key pair(pkv, skv) by given public parameters
func KeyGen() (pubkey PublicKey, privkey PrivateKey, leaveHashes [][]byte) {
	pp := &PublicParameter{N: 1024, T: 16}
	r, _ := GenRandomBytes(64)
	var i int32
	var rootList [][]byte
	var leaves = make([][]byte, pp.N)
	var xi0 = make([][]byte, pp.N)
	for i = 0; i < pp.N; i++ {
		xi0[i] = CalculateHash(append(r, []byte(strconv.Itoa(int(i)))...))
	}
	for i = 0; i < pp.N; i++ {
		var jRoot = xi0[i]
		var j int32
		for j = 0; j < pp.T; j++ {
			jRoot = CalculateHash(jRoot[:])
		}
		rootList = append(rootList, jRoot[:])
		leaves[i] = jRoot
	}
	var intermediateHashes = make(map[int][][]byte)
	pk := ComputeMerkleRoot(leaves, intermediateHashes)
	log.Println("Generated Merkle Root:", hex.EncodeToString(pk[:]))
	//for treeHeight := 1; treeHeight <= len(intermediateHashes); treeHeight++ {
	//	log.Println("[IntermediateHash]", treeHeight, len(intermediateHashes[treeHeight]), intermediateHashes[treeHeight])
	//}
	sk := [64]byte{}
	copy(sk[:], r)
	return pk, sk, leaves
}

// Eval return VRF value and its accompanying proof pi by given message x ∈ {0,1}^m(l)
//  𝜇 is the VRF input/message
func (sk PrivateKey) Eval(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32) (proof VrfProof, ok bool, ap *Branch) {
	rSk64 := [64]byte{}
	copy(rSk64[:], sk[:])
	xi0 := CalculateHash(append(rSk64[:], []byte(strconv.Itoa(int(i)))...))
	var iter int32
	for iter = 0; iter < (16 - 1 - j); iter++ {
		xi0 = CalculateHash(xi0[:])
	}
	v := CalculateHash(append(xi0[:], mu[:]...))
	authPath := CalculateAuthPath(leaveHashes, leaveHashes[i])
	// return v, y, ap
	appendProof := [64]byte{}
	copy(appendProof[:], append(v[:], xi0[:]...))
	copy(proof[:], appendProof[:])
	return proof, true, authPath
}

func (pk PublicKey) Verify(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32, proof VrfProof, ap *Branch) int {
	v := proof[:32]
	y := proof[32:]
	newProof := CalculateHash(append(y, mu[:]...))
	if !bytes.Equal(v, newProof[:]) {
		return 0
	}
	var iter int32
	for iter = 0; iter < j+1; iter++ {
		newY := CalculateHash(y)
		copy(y, newY[:])
	}
	yDigest := [32]byte{}
	copy(yDigest[:], y)
	apXit := CalculateAuthPath(leaveHashes, leaveHashes[i])
	merkleRoot1, _ := VerifyAuthPath(ap)
	merkleRoot2, _ := VerifyAuthPath(apXit)
	log.Println(merkleRoot1, merkleRoot2)
	if bytes.Equal(pk[:], merkleRoot1[:]) && bytes.Equal(pk[:], merkleRoot2[:]) {
		return 1
	}
	return 0
}

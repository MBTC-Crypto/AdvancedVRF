package vrf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cbergoon/merkletree"
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
func KeyGen(pp PublicParameter) (pubkey PublicKey, privkey PrivateKey, t *merkletree.MerkleTree) {
	r, _ := Message{Msg: "MT-iVRF"}.CalculateHash()
	r32 := [32]byte{}
	copy(r32[:], r)
	var i int32 = 0
	// i [0,N-1]
	// 1. x00,x01, ... , x0t-1

	//var rootList [][]byte
	var rootList []merkletree.Content
	for i < pp.N {
		// Xi,0 = Hash(r,i) => [x00,x10,x20,...,xN-1 0]
		//xi0, _ := Message{Msg: hex.EncodeToString(r) + strconv.Itoa(int(i))}.CalculateHash()
		i32 := [32]byte{}
		copy(i32[:], strconv.Itoa(int(i)))
		concatMessage := hex.EncodeToString(ConcatDigests(&r32, &i32)[:])
		xi0, _ := Message{Msg: concatMessage}.CalculateHash()
		//log.Println(hex.EncodeToString(xi0), strconv.Itoa(int(i)), strconv.Itoa(int(0)))
		var jRoot = xi0
		var j int32 = 0
		// Hash(xi,j) t-1 times 1,...,t-1
		for j < pp.T {
			k32 := [32]byte{}
			copy(k32[:], strconv.Itoa(int(j+1)))
			jRoot32 := [32]byte{}
			copy(jRoot32[:], jRoot)
			//jRoot, _ = Message{Msg: hex.EncodeToString(jRoot) + strconv.Itoa(int(i)) + strconv.Itoa(int(j+1))}.CalculateHash()
			jRootMessage := hex.EncodeToString(ConcatDigests(&jRoot32, &i32, &k32)[:])
			//log.Println(hex.EncodeToString(jRoot), jRootMessage, strconv.Itoa(int(i)), strconv.Itoa(int(j)))
			jRoot, _ = Message{Msg: jRootMessage}.CalculateHash()
			j++
		}
		// 3. X0t, X1t,...XNt j = t
		// TODO Do i need to use parameters i and j into the Hash function?
		rootList = append(rootList, Message{Msg: hex.EncodeToString(jRoot)})
		i++
	}
	// TODO Build Merkle tree using
	// create a NEW Merkle Tree from the list of content
	log.Println("Elements Number:", len(rootList))

	tree, err := merkletree.NewTree(rootList)
	if err != nil {
		log.Fatal(err)
	}
	root := tree.MerkleRoot()
	log.Println("Generated Merkle Root:", hex.EncodeToString(root))
	return root, r, tree
}

// Eval return VRF value and its accompanying proof pi by given message x ∈ {0,1}^m(l)
//  𝜇 is the VRF input/message
func (sk PrivateKey) Eval(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32) (vrfValue, vrfProof []byte, ap *Branch) {
	// Compute xi = Hash(r,i) for r = skv,
	i32 := [32]byte{}
	copy(i32[:], strconv.Itoa(int(i)))
	rSk32 := [32]byte{}
	copy(rSk32[:], sk)
	concatMessage := hex.EncodeToString(ConcatDigests(&rSk32, &i32)[:])
	xi0, _ := Message{Msg: concatMessage}.CalculateHash()
	fmt.Println("x10", hex.EncodeToString(xi0))
	// Compute v = PRF.Eval(x) = H(y,x)
	xi032 := [32]byte{}
	copy(xi032[:], xi0[:])
	vMessage := hex.EncodeToString(ConcatDigests(&xi032, &mu)[:])
	//vrfValue, _ = Message{Msg: hex.EncodeToString(xi0)}.CalculateHash()
	for (16 - 1 - j) > 0 {
		xi0, _ = Message{Msg: hex.EncodeToString(xi0)}.CalculateHash()
		j--
	}
	vrfValue = xi0
	log.Println("vrfValue:", hex.EncodeToString(vrfValue), " \nvrfProof:", vMessage)
	//return vrfValue, ConcatDigests(&xi032, &mu)[:]
	log.Println("leavesHashArr", len(leaveHashes))
	// xi : leaveHashes[i]
	ap = CalculateAuthPath(leaveHashes, leaveHashes[i])
	// mb : 10 hash values. only need 10 steps computations.
	return vrfValue, xi0, ap
}

func (pk PublicKey) Verify(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32, vrfValue, vrfProof []byte, ap *Branch) int {
	log.Println("Output VrfValue:", hex.EncodeToString(vrfValue))
	log.Println("Output VrfProof:", hex.EncodeToString(vrfProof))
	vrfProof32 := [32]byte{}
	copy(vrfProof32[:], vrfProof)
	verifyMessage := hex.EncodeToString(ConcatDigests(&vrfProof32, &mu)[:])
	newVrfValue, _ := Message{Msg: verifyMessage}.CalculateHash()
	log.Println("Output NewVrfValue:", hex.EncodeToString(newVrfValue))
	res := bytes.Compare(newVrfValue, vrfValue)
	if res == 0 {
		log.Println("NewVrfValue and VrfValue are equal!")
	} else {
		log.Println("NewVrfValue and VrfValue are not equal!")
		return 1
	}
	// Compare v == H(y,x)
	log.Println("NewVrfValue", hex.EncodeToString(newVrfValue))
	log.Println("OrigVRFValue:", hex.EncodeToString(vrfValue))
	// Compute xi = H^j+1(y)
	var count int
	for (j + 1) > 0 {
		a, _ := Message{Msg: hex.EncodeToString(vrfProof32[:])}.CalculateHash()
		copy(mu[:], a)
		j--
		count++
	}
	log.Println(hex.EncodeToString(mu[:]))
	//xi, _ := Message{Msg: hex.EncodeToString(vrfProof)}.CalculateHash()
	// Compute Merkel root pk' by xi through AP, then compare pk' and pk
	authPathXi := CalculateAuthPath(leaveHashes, &mu)
	//authPathIndex := CalculateAuthPath(leaveHashes, leaveHashes[i])
	//authPathProof := ap
	merkleRoot1, _ := VerifyAuthPath(authPathXi)
	//merkleRoot2, _ := VerifyAuthPath(authPathIndex)
	//merkleRoot3, _ := VerifyAuthPath(authPathProof)

	//log.Println(bytes.Compare(merkleRoot1[:], pk), bytes.Compare(merkleRoot2[:], pk), bytes.Compare(merkleRoot3[:], pk))
	return bytes.Compare(merkleRoot1[:], pk)
}

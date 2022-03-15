package vrf

import (
	"bytes"
	"encoding/hex"
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
			log.Println(hex.EncodeToString(jRoot), jRootMessage, strconv.Itoa(int(i)), strconv.Itoa(int(j)))
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
func (sk PrivateKey) Eval(x string, i, j int32, tree *merkletree.MerkleTree) (vrfValue, vrfProof []byte) {
	log.Println("sk", hex.EncodeToString(sk))
	// Compute xi = Hash(r,i) for r = skv,
	xi0, _ := Message{Msg: hex.EncodeToString(sk) + strconv.Itoa(int(i))}.CalculateHash()
	// Compute y = H^(t-1-j)(xi,0)
	yExp := 16 - 1 - j
	var yValue, _ = Message{Msg: hex.EncodeToString(xi0)}.CalculateHash()
	var e int32 = 1
	for e < yExp {
		yValue, _ = Message{Msg: hex.EncodeToString(yValue)}.CalculateHash()
		e++
	}
	// Compute v = PRF.Eval(x) = H(y,x)
	vrfValue, _ = Message{Msg: hex.EncodeToString(yValue) + x}.CalculateHash()
	log.Println("vrfValue:", vrfValue, " \nvrfProof:", yValue)
	return vrfValue, yValue
}

func (pk PublicKey) Verify(x string, i, j int32, vrfValue, vrfProof []byte) bool {
	log.Println("PublicKey Verify: \n\tVrfValue:", hex.EncodeToString(vrfValue), " \n\tVrfProof:", hex.EncodeToString(vrfProof))
	newVrfValue, _ := Message{Msg: hex.EncodeToString(vrfProof) + x}.CalculateHash()
	res := bytes.Compare(newVrfValue, vrfValue)
	if res == 0 {
		log.Println("!..Slices are equal..!")
	} else {
		log.Println("!..Slice are not equal..!")
		return false
	}
	// Compare v == H(y,x)
	log.Println("VRF Value:\n\tNewVrfValue", hex.EncodeToString(newVrfValue), "\n\tOrigVRFValue:", hex.EncodeToString(vrfValue))
	// Compute xit = H^(j+1)(y)
	var iRootList []merkletree.Content
	xi0, _ := Message{Msg: hex.EncodeToString(vrfProof)}.CalculateHash() // xi0\
	var jRoot = xi0
	iRootList = append(iRootList, Message{Msg: hex.EncodeToString(jRoot)})
	//var T int32 = 16
	var t int32 = 1
	// t from 1 to 15
	for t < j {
		jRoot, _ = Message{Msg: hex.EncodeToString(jRoot)}.CalculateHash()
		iRootList = append(iRootList, Message{Msg: hex.EncodeToString(jRoot)})
		t++
	}
	log.Println(len(iRootList))
	// Construct a Merkle root'
	iTree, err := merkletree.NewTree(iRootList)
	if err != nil {
		log.Fatal(err)
	}

	iRoot := iTree.MerkleRoot()
	log.Println("Generated New Xi0:", hex.EncodeToString(xi0))
	log.Println("Generated Merkle Root:", hex.EncodeToString(iRoot))
	log.Println("Generated Public Key:", hex.EncodeToString(pk))
	log.Println(len(iTree.Leafs))
	//for it := 0; it < 16; it++ {
	//	log.Println("iTree Tree Leave", hex.EncodeToString(iTree.Leafs[it].Hash), iTree.Leafs[it].C)
	//}
	return true
}

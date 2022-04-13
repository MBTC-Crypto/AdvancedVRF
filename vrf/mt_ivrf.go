package vrf

import (
	"bytes"
	"crypto/sha256"
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
	var leaves = make([][32]byte, pp.N)
	for i < pp.N {
		// Xi,0 = Hash(r,i) => [x00,x10,x20,...,xN-1 0]
		//xi0, _ := Message{Msg: hex.EncodeToString(r) + strconv.Itoa(int(i))}.CalculateHash()
		var j int32 = 0
		i32 := [32]byte{}
		j32 := [32]byte{}
		copy(i32[:], strconv.Itoa(int(i)))
		copy(j32[:], strconv.Itoa(int(j)))
		concatMessage := hex.EncodeToString(ConcatDigests(&r32, &i32, &j32)[:])
		xi0, _ := Message{Msg: concatMessage}.CalculateHash()
		//log.Println(hex.EncodeToString(xi0), strconv.Itoa(int(i)), strconv.Itoa(int(0)))
		var jRoot = xi0

		// Hash(xi,j) t-1 times 1,...,t-1
		count := 0
		for j < pp.T {
			k32 := [32]byte{}
			copy(k32[:], strconv.Itoa(int(j+1)))
			jRoot32 := [32]byte{}
			copy(jRoot32[:], jRoot)
			//jRoot, _ = Message{Msg: hex.EncodeToString(jRoot) + strconv.Itoa(int(i)) + strconv.Itoa(int(j+1))}.CalculateHash()
			jRootMessage := hex.EncodeToString(ConcatDigests(&jRoot32, &i32, &k32)[:])
			jRoot, _ = Message{Msg: jRootMessage}.CalculateHash()
			//log.Println("=======", jRootMessage, hex.EncodeToString(jRoot), i, j+1)
			j++
			count++
		}
		// 3. X0t, X1t,...XNt j = t
		//log.Println("Index:", i, j)
		rootList = append(rootList, Message{Msg: hex.EncodeToString(jRoot)})
		leave := [32]byte{}
		copy(leave[:], jRoot)
		leaves[i] = leave
		i++
	}
	//log.Println("rootList", rootList)
	// create a NEW Merkle Tree from the list of content
	log.Println("Elements Number:", len(rootList))
	tree, err := merkletree.NewTree(rootList)
	if err != nil {
		log.Fatal(err)
	}
	//root := tree.MerkleRoot()
	//log.Println("Generated Merkle Root:", hex.EncodeToString(root))
	//var myRoot [32]byte
	var intermediateHashes = make(map[int][][32]byte)
	root := ComputeMerkleRoot(leaves, intermediateHashes)
	log.Println("Generated Merkle Root:", hex.EncodeToString(root[:]))
	for treeHeight := 1; treeHeight <= len(intermediateHashes); treeHeight++ {
		log.Println("intermediateHash=====", treeHeight, len(intermediateHashes[treeHeight]), intermediateHashes[treeHeight])
	}
	return root, r, tree
}

// Eval return VRF value and its accompanying proof pi by given message x ∈ {0,1}^m(l)
//  𝜇 is the VRF input/message
func (sk PrivateKey) Eval(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32) (vrfValue, vrfProof []byte, ap *Branch) {
	// Compute xi = Hash(r,i) for r = skv,
	i32 := [32]byte{}
	j32 := [32]byte{}
	copy(i32[:], strconv.Itoa(int(i)))
	copy(j32[:], strconv.Itoa(int(j)))
	rSk32 := [32]byte{}
	copy(rSk32[:], sk)
	concatMessage := hex.EncodeToString(ConcatDigests(&rSk32, &i32)[:])
	xi0, _ := Message{Msg: concatMessage}.CalculateHash()
	log.Println("Eval-[x10]-Before:", hex.EncodeToString(xi0))
	// Compute v = PRF.Eval(x) = H(y,x)
	//vrfValue, _ = Message{Msg: hex.EncodeToString(xi0)}.CalculateHash()
	iter := 16 - 1 - j
	if iter > 0 {
		for iter > 0 {
			xi0, _ = Message{Msg: hex.EncodeToString(xi0)}.CalculateHash()
			//log.Println(xi0)
			iter--
		}
	}
	xi032 := [32]byte{}
	copy(xi032[:], xi0[:])
	log.Println("Eval-[x10]-After:", hex.EncodeToString(xi0), hex.EncodeToString(xi032[:]))
	// y = H^(t-1-j)(xi0) = xi032
	// v = H(y,mu)
	vMessage := hex.EncodeToString(ConcatDigests(&xi032, &mu)[:])
	log.Println("vMessage:", vMessage)
	vrfValue, _ = Message{Msg: vMessage}.CalculateHash()
	log.Println("vrfValue:", hex.EncodeToString(vrfValue))
	// xi : leaveHashes[i]
	// compute an authentication path APi with regard to the leaf index i
	log.Println("leaveHashes[i]", hex.EncodeToString((*leaveHashes[i])[:]))
	authPath := CalculateAuthPath(leaveHashes, leaveHashes[i])
	// mb : 10 hash values. only need 10 steps computations.
	//pi := [64]byte{}
	return vrfValue, xi0, authPath
}

func (pk PublicKey) Verify(mu [32]byte, leaveHashes []*[sha256.Size]byte, i, j int32, vrfValue, vrfProof []byte, ap *Branch) int {
	//log.Println("Output VrfValue:", hex.EncodeToString(vrfValue))
	//log.Println("Output VrfProof:", hex.EncodeToString(vrfProof))
	// y-value
	vrfProof32 := [32]byte{}
	copy(vrfProof32[:], vrfProof)
	//log.Println("Output VrfProof32:", hex.EncodeToString(vrfProof32[:]))
	yMessage := hex.EncodeToString(ConcatDigests(&vrfProof32, &mu)[:])
	newVrfProof32, _ := Message{Msg: yMessage}.CalculateHash()
	//log.Println("Output newVrfProof32:", hex.EncodeToString(newVrfProof32))
	// check if v != H(y,mu)
	if !bytes.Equal(vrfValue, newVrfProof32) {
		log.Println("NewVrfValue and VrfValue are not equal!")
		return 0
	}
	// Compare v == H(y,x)
	//log.Println("newVrfProof", hex.EncodeToString(newVrfProof32))
	//log.Println("OrigVRFValue:", hex.EncodeToString(vrfValue))
	// Compute xit = H^j+1(y)
	iter := j + 1
	xit32 := [32]byte{}
	//log.Println("[xit32]-Before:", hex.EncodeToString(xit32[:]))
	for iter > 0 {
		vrfProof, _ = Message{Msg: hex.EncodeToString(vrfProof)}.CalculateHash()
		iter--
	}
	//log.Println("[xit32]-After:", hex.EncodeToString(vrfProof))
	// Compute Merkel root pk' by xi through AP, then compare pk' and pk
	copy(xit32[:], vrfProof)
	//log.Println("xit32", hex.EncodeToString(xit32[:]))
	apXit := CalculateAuthPath(leaveHashes, &xit32)
	//log.Println("----------------->[i]", hex.EncodeToString(leaveHashes[i][:]))
	apIndex := CalculateAuthPath(leaveHashes, leaveHashes[i])
	//for t, hash := range apIndex.Hashes {
	//	log.Println(t, hex.EncodeToString(hash[:]))
	//}
	combinedMsg := ConcatDigests((*[32]byte)(ap.Hashes[8][:]), (*[32]byte)(ap.Hashes[9][:])) // 1020,1021 -> 510
	log.Println("1020+[1021] -> [510]", hex.EncodeToString(combinedMsg[:]))
	combinedMsg = ConcatDigests(combinedMsg, (*[32]byte)(ap.Hashes[10][:])) // 510 - 511 -> 255
	log.Println("[510] + 511 -> [255]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[7][:]), combinedMsg) // 254 - 255 -> 127
	log.Println("254 + [255] -> [127]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[6][:]), combinedMsg) // 126 - 127 -> 63
	log.Println("126 + [127] -> [63]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[5][:]), combinedMsg) // 62 - 63 -> 31
	log.Println("62 + [63] -> [31]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[4][:]), combinedMsg) // 30 - 31 -> 15
	log.Println("30 + [31] -> [15]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[3][:]), combinedMsg) // 14 - 15 -> 7
	log.Println("14 + [15] -> [7]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[2][:]), combinedMsg) // 6 - 7 -> 3
	log.Println("6 + [7] -> [3]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[1][:]), combinedMsg) // 2 - 3 -> 1
	log.Println("2 + [3] -> [1]", hex.EncodeToString(combinedMsg[:]))

	combinedMsg = ConcatDigests((*[32]byte)(ap.Hashes[0][:]), combinedMsg) // 0 - 1 -> Root'
	merkleRoot1, _ := VerifyAuthPath(apXit)
	merkleRoot2, _ := VerifyAuthPath(ap)
	merkleRoot3, _ := VerifyAuthPath(apIndex)
	log.Println("merkleRoot1:", hex.EncodeToString(merkleRoot1[:]))
	log.Println("merkleRoot2:", hex.EncodeToString(merkleRoot2[:]))
	log.Println("merkleRoot3:", hex.EncodeToString(merkleRoot3[:]))
	log.Println("rootPrime:", hex.EncodeToString(combinedMsg[:]))
	log.Println("Pk:", hex.EncodeToString(pk[:]))
	if bytes.Compare(merkleRoot1[:], merkleRoot2[:]) != 0 || bytes.Compare(merkleRoot1[:], pk[:]) != 0 {
		return 0
	}
	return 1
}

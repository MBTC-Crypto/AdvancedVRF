package vrf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strconv"
	"strings"

	"github.com/cbergoon/merkletree"
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
	var allLeaves []merkletree.Content
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
		allLeaves = append(allLeaves, Message{Msg: hex.EncodeToString(jRoot)})
		i++
	}
	// create a NEW Merkle Tree from the list of content
	log.Println("Elements Number:", len(allLeaves))
	tree, err := merkletree.NewTree(allLeaves)
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
	log.Println("Output VrfValue:", hex.EncodeToString(vrfValue))
	log.Println("Output VrfProof:", hex.EncodeToString(vrfProof))
	// y-value
	vrfProof32 := [32]byte{}
	copy(vrfProof32[:], vrfProof)
	log.Println("Output VrfProof32:", hex.EncodeToString(vrfProof32[:]))
	yMessage := hex.EncodeToString(ConcatDigests(&vrfProof32, &mu)[:])
	newVrfProof32, _ := Message{Msg: yMessage}.CalculateHash()
	log.Println("Output newVrfProof32:", hex.EncodeToString(newVrfProof32))
	// check if v != H(y,mu)
	res := bytes.Compare(vrfValue, newVrfProof32)
	if res == 0 {
		log.Println("NewVrfValue and VrfValue are equal!")
	} else {
		log.Println("NewVrfValue and VrfValue are not equal!")
		return 0
	}
	// Compare v == H(y,x)
	log.Println("newVrfProof", hex.EncodeToString(newVrfProof32))
	log.Println("OrigVRFValue:", hex.EncodeToString(vrfValue))
	// Compute xit = H^j+1(y)
	iter := j + 1
	xit32 := [32]byte{}
	log.Println("[xit32]-Before:", hex.EncodeToString(xit32[:]))
	for iter > 0 {
		vrfProof, _ = Message{Msg: hex.EncodeToString(vrfProof)}.CalculateHash()
		iter--
	}
	log.Println("[xit32]-After:", hex.EncodeToString(vrfProof))
	// Compute Merkel root pk' by xi through AP, then compare pk' and pk
	copy(xit32[:], vrfProof)
	log.Println("xit32", hex.EncodeToString(xit32[:]))
	apXit := CalculateAuthPath(leaveHashes, &xit32)
	apIndex := CalculateAuthPath(leaveHashes, leaveHashes[i])
	// for t, hash := range apIndex.Hashes {
	// 	log.Println(t, hex.EncodeToString(hash[:]))
	// }
	bitMap := Bytes2bits(ap.Flags)
	log.Println("bitMap", bitMap)
	// TODO Need to be updated soon
	// //1021
	// for idx := 0; idx < len(bitMap); {
	// 	flag := Bytes2Int(bitMap[idx:idx+2], 1)
	// 	log.Println(flag)
	// 	if flag == 0 {
	// 		log.Println("=====NOTHING=====")
	// 	} else if flag == 1 {
	// 		log.Println("=====Same Height, Select a left node=====")
	// 	} else if flag == 2 {
	// 		log.Printf("=====left=====")
	// 	} else if flag == 3 {
	// 		log.Printf("=====left=====")
	// 	} else {
	// 		log.Println("======WRONG=====")
	// 	}
	// 	idx += 2
	// }
	rootPrime := ConcatDigests(&apIndex.Hashes[8], &apIndex.Hashes[9])
	rootPrime = ConcatDigests(rootPrime, &apIndex.Hashes[10])
	for idx := 7; idx >= 0; idx-- {
		log.Println(hex.EncodeToString((&apIndex.Hashes[idx])[:]), hex.EncodeToString((rootPrime)[:]))
		rootPrime = ConcatDigests(&apIndex.Hashes[idx], rootPrime)
	}
	merkleRoot1, _ := VerifyAuthPath(apXit)   // Calculated by xi
	merkleRoot2, _ := VerifyAuthPath(ap)      // Calculated by ap from Eval
	merkleRoot3, _ := VerifyAuthPath(apIndex) // Calculated by index i
	log.Println(hex.EncodeToString(merkleRoot1[:]), hex.EncodeToString(merkleRoot2[:]), hex.EncodeToString(merkleRoot3[:]))
	log.Println("[RootPrime]", hex.EncodeToString(rootPrime[:]))
	log.Println("[apXit]", hex.EncodeToString((&apXit.Hashes[0])[:]))
	log.Println("[PK]", hex.EncodeToString(pk))
	if (!bytes.Equal(merkleRoot1[:], rootPrime[:])) || (!bytes.Equal(merkleRoot2[:], rootPrime[:])) {
		return 0
	}
	return 1
}

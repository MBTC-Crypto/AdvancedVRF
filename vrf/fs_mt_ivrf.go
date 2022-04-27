package vrf

//
//import (
//	"crypto/ed25519"
//	"crypto/sha256"
//	"encoding/hex"
//	"github.com/cbergoon/merkletree"
//	"log"
//	"strconv"
//)
//
//func Keygen(pp PublicParameter) (pubkey PublicKey, privkey PrivateKey, t *merkletree.MerkleTree) {
//	r, _ := Message{Msg: "FS-MT-iVRF"}.CalculateHash()
//	r32 := [32]byte{}
//	copy(r32[:], r)
//	var i int32 = 0
//	var rootList []merkletree.Content
//	var leaves = make([][]byte, pp.N)
//
//	for i < pp.N {
//		i32 := [32]byte{}
//		copy(i32[:], strconv.Itoa(int(i)))
//		concatMessage := hex.EncodeToString(ConcatDigests(&r32, &i32)[:])
//		xi0, _ := Message{Msg: concatMessage}.CalculateHash() // Same as mt_ivrf keygen
//		ski := ed25519.NewKeyFromSeed(xi0)
//		pki := ski.Public().(ed25519.PublicKey)
//		concatKeyMessage := hex.EncodeToString(ConcatDigests((*[32]byte)(xi0), (*[32]byte)(pki))[:])
//		xi1, _ := Message{Msg: concatKeyMessage}.CalculateHash()
//		// 3. X01, X21,...Xn1
//		rootList = append(rootList, Message{Msg: hex.EncodeToString(xi1)})
//		leave := [32]byte{}
//		copy(leave[:], xi1)
//		leaves[i] = leave
//		i++
//	}
//	tree, err := merkletree.NewTree(rootList)
//	if err != nil {
//		log.Fatal(err)
//	}
//	var intermediateHashes = make(map[int][][]byte)
//
//	root := ComputeMerkleRoot(leaves, intermediateHashes)
//	log.Println("Generated Merkle Root:", hex.EncodeToString(root[:]))
//	log.Println("intermediateHashes", intermediateHashes[1])
//	return root, r, tree
//}
//
//func (sk PrivateKey) EvalSign(mu1, mu2 [32]byte, leaveHashes []*[sha256.Size]byte, i int32) (vrfValue, vrfProof []byte, mb *Branch) {
//	i32 := [32]byte{}
//	copy(i32[:], strconv.Itoa(int(i)))
//	rSk32 := [32]byte{}
//	copy(rSk32[:], sk)
//	concatMessage := hex.EncodeToString(ConcatDigests(&rSk32, &i32)[:])
//	xi0, _ := Message{Msg: concatMessage}.CalculateHash()
//	xi032 := [32]byte{}
//	copy(xi032[:], xi0[:])
//	vMessage := hex.EncodeToString(ConcatDigests(&xi032, &mu1)[:])
//	vrfValue, _ = Message{Msg: vMessage}.CalculateHash()
//	log.Println("vrfValue:", vrfValue, " \nvrfProof:", vMessage)
//	return []byte{}, []byte{}, nil
//}

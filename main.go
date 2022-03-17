package main

import (
	"AdvancedVRF/vrf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cbergoon/merkletree"
	"log"
	"strconv"
)

func main() {
	fmt.Println("===================ParamGen===================")
	pg := vrf.ParamGen("16-1024")
	fmt.Println("PG.N", pg.N)
	fmt.Println("PG.t", pg.T)

	fmt.Println("===================KeyGen===================")
	pp := vrf.PublicParameter{
		T: pg.T,
		N: pg.N,
	}
	pk, sk, tree := vrf.KeyGen(pp)
	//hex.EncodeToString(pk)
	log.Println("pkv(Merkle Root):", hex.EncodeToString(pk), "skv(r):", hex.EncodeToString(sk))
	vt, err := tree.VerifyTree()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verify Tree:", vt)
	// verify the entire tree is valid
	var list1 []merkletree.Content
	//rStr := "b086566725a494d80fff45333aeb62e9df7798afd5325b4dc3328d0b72791ecb"
	v1t, _ := vrf.Message{Msg: "09a747437dc53affaaa65f9e2517876f3a7b892741891aa2d26a9fc5d07102ec" + strconv.Itoa(980) + strconv.Itoa(15)}.CalculateHash()
	v1f1, _ := vrf.Message{Msg: "09a747437dc53affaaa65f9e2517876f3a7b892741891aa2d26a9fc5d07102ec" + strconv.Itoa(980) + strconv.Itoa(16)}.CalculateHash()
	v1f2, _ := vrf.Message{Msg: "f14db492ceaecc3297efdf3fd4550503eabf1e3444bbc28b55d7d48f5f244486" + strconv.Itoa(1002) + strconv.Itoa(16)}.CalculateHash()

	v2t, _ := vrf.Message{Msg: "956fdaedd2dfc8894f23916c6291d1115bbbce6b517851d6efa2282af44df4f5" + strconv.Itoa(1021) + strconv.Itoa(16)}.CalculateHash()
	v2f1, _ := vrf.Message{Msg: "c87ae3142d097e7087bec5ea041c3ae82f5fc3a84ce21a3a20a837da928f29e6" + strconv.Itoa(1022) + strconv.Itoa(16)}.CalculateHash()
	v2f2, _ := vrf.Message{Msg: "ed4a61bc5242248591d86b72107e315c1bdb723387105f7fedbcd31fc049983f" + strconv.Itoa(1022) + strconv.Itoa(16)}.CalculateHash()
	msg32, i32, k32 := [32]byte{}, [32]byte{}, [32]byte{}
	decodedHex, _ := hex.DecodeString("96dfb59973d305951e8a3d5d2eddf3c65c09a5d5b92f05ff9d7ee224e2f993d0")
	copy(msg32[:], decodedHex)
	copy(i32[:], strconv.Itoa(int(1023)))
	copy(k32[:], strconv.Itoa(int(16)))
	message := hex.EncodeToString(vrf.ConcatDigests(&msg32, &i32, &k32)[:])
	v3t, _ := vrf.Message{Msg: message}.CalculateHash()
	v3f1, _ := vrf.Message{Msg: "945fe37e6d374d55241e4bd6752224a2849ec9809612ff09e70e885348d5b7c0"}.CalculateHash()
	v3f2, _ := vrf.Message{Msg: "500172adfa38bb778b462a89463fa3fb249a6b1164c3422b4cb81d688524648f"}.CalculateHash()

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1f1)}) // false
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1f2)}) // false

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2f1)}) // false
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2f2)}) // false

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v3t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v3f1)}) // false
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v3f2)}) // false
	//3fa148e3af80065ae1d5dac200b9ea1c41374601c0a97a1441d3bd05db295574 989eb61064c3452618e3c58c3a4ccac5af4e261a38e34563f4149de121bda639 15 16
	// TODO Can test with rootList
	for _, message := range list1 {
		vc, err := tree.VerifyContent(message)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Verify Content:", vc)
	}
	//treePath, index, _ := tree.GetMerklePath(list1[8])
	//log.Println("merklePath", merklePath)
	//log.Println("Index", index)
	//log.Println("TreePath", treePath)
	// 0 [1] 2^10 = 1024 1023 1111 2^10 - 1024
	leavesHashArr := [1024]*[sha256.Size]byte{}
	for i, leave := range tree.Leafs {
		// Check two leaves have same parents
		//log.Println(i, leave.Hash)
		leaveHash32 := [32]byte{}
		copy(leaveHash32[:], leave.Hash)
		leavesHashArr[i] = &leaveHash32
	}
	log.Println("PK", hex.EncodeToString(pk))
	log.Println("===================sk.Eval===================")
	x9 := "500172adfa38bb778b462a89463fa3fb249a6b1164c3422b4cb81d688524648f" // 1023 15
	x9Hex, _ := hex.DecodeString(x9)
	x9Hex32 := [32]byte{}
	copy(x9Hex32[:], x9Hex)
	vrfValue, vrfProof, authPath := sk.Eval(x9Hex32, leavesHashArr[:], 1023, 15)
	log.Println("Output VRF Value", hex.EncodeToString(vrfValue))
	log.Println("Output VRF Hex Value", vrfValue)
	log.Println("Output VRF Proof", hex.EncodeToString(vrfProof))
	//get the path list1[6] 1023
	log.Println("===================pk.Verify===================")
	//𝑦 is 𝑥𝑖,0 in above sk.Eval
	// 5f79a6037e15bddf142030a9d16ca9b8fd59c62b46a58ace8d88026f81ee96a5
	// ad42879f0f32ed23bd619fb592df1f0cab1a60e3145a4d693baa2edd25e3ae26 1023 7
	x7 := "ad42879f0f32ed23bd619fb592df1f0cab1a60e3145a4d693baa2edd25e3ae26"
	x7Hex, _ := hex.DecodeString(x7)
	x7Hex32 := [32]byte{}
	copy(x7Hex32[:], x7Hex)
	output := pk.Verify(x7Hex32, leavesHashArr[:], 1023, 7, vrfValue, vrfProof, authPath)
	log.Println("Verify result:", output)

	//newHash := vrf.ConcatDigests((*[32]byte)(tree.Leafs[0].Hash), (*[32]byte)(tree.Leafs[1].Hash))
	//log.Println(*newHash)
	//pkvs, skvs, _ := vrf.Keygen(pp)
	//log.Println("pkvs", pkvs)
	//log.Println("skvs", skvs)
}

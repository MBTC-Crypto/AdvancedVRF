package main

import (
	"AdvancedVRF/vrf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cbergoon/merkletree"
	"log"
	"reflect"
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
	v2f2, _ := vrf.Message{Msg: "185026d89e8de9b77f716a971c61bbeed73ecb8792957285ec70f56cd108acc7" + strconv.Itoa(1023) + strconv.Itoa(15)}.CalculateHash()
	msg32, i32, k32 := [32]byte{}, [32]byte{}, [32]byte{}
	decodedHex, _ := hex.DecodeString("697df527ca1b476b225b9af9af04f6ca1292301d370f9baba0a0e02632966785")
	copy(msg32[:], decodedHex)
	copy(i32[:], strconv.Itoa(int(1023)))
	copy(k32[:], strconv.Itoa(int(16)))
	message1 := hex.EncodeToString(vrf.ConcatDigests(&msg32, &i32, &k32)[:])
	v3t, _ := vrf.Message{Msg: message1}.CalculateHash()

	decodedHex2, _ := hex.DecodeString("aa22f6eb0d9cd4eafc01f5ad99bfb5446ea897fe60a563c0977966bb84a065fa")
	msg232, i232, k232 := [32]byte{}, [32]byte{}, [32]byte{}
	copy(msg232[:], decodedHex2)
	copy(i232[:], strconv.Itoa(int(1022)))
	copy(k232[:], strconv.Itoa(int(16)))
	message2 := hex.EncodeToString(vrf.ConcatDigests(&msg232, &i232, &k232)[:])
	v3t2, _ := vrf.Message{Msg: message2}.CalculateHash()

	v3f1, _ := vrf.Message{Msg: "945fe37e6d374d55241e4bd6752224a2849ec9809612ff09e70e885348d5b7c0"}.CalculateHash()
	v3f2, _ := vrf.Message{Msg: "697df527ca1b476b225b9af9af04f6ca1292301d370f9baba0a0e02632966785"}.CalculateHash()

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1f1)}) // false
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v1f2)}) // false

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2f1)}) // false
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v2f2)}) // false

	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v3t)})  // true
	list1 = append(list1, vrf.Message{Msg: hex.EncodeToString(v3t2)}) // true
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
	for i, _ := range tree.Leafs {
		// Check two leaves have same parents
		s := reflect.ValueOf(tree.Leafs[i].C)
		leaveHash32 := [32]byte{}
		decodeBytes, _ := hex.DecodeString(s.Interface().(vrf.Message).Msg)
		copy(leaveHash32[:], decodeBytes)
		leavesHashArr[i] = &leaveHash32
	}
	log.Println(tree.Leafs[1022].Parent == tree.Leafs[1023].Parent)
	log.Println(tree.Leafs[1021].Parent == tree.Leafs[1020].Parent)

	log.Println("PK", hex.EncodeToString(pk))
	log.Println("===================sk.Eval===================")
	//log.Println(leavesHashArr[1023])
	// 2de234baea20e96aeb604a008d049339c9b67da1bc64872b7703c498b383b673 996 16
	// 3754d05c0a7ea22e80491b95efac123247ed06398027090496a1abac11e423d5 996 10
	mu := "d084db3416cb1196b6bf7ee0e7383361096b9811bb5cb088dde7c453efd4a1ce" // 996 10
	muHex, _ := hex.DecodeString(mu)
	muHex32 := [32]byte{}
	copy(muHex32[:], muHex)
	i := 1021
	j := 16
	// v, pi(y,ap)
	vrfValue, vrfProof, authPath := sk.Eval(muHex32, leavesHashArr[:], int32(i), int32(j))
	log.Println("Output VRF Value", hex.EncodeToString(vrfValue))
	log.Println("Output VRF Hex Value", vrfValue)
	log.Println("Output VRF Proof", hex.EncodeToString(vrfProof))
	//log.Println(authPath)
	//get the path list1[6] 1023
	log.Println("===================pk.Verify===================")
	//𝑦 is 𝑥𝑖,0 in above sk.Eval
	// 5f79a6037e15bddf142030a9d16ca9b8fd59c62b46a58ace8d88026f81ee96a5
	// ad42879f0f32ed23bd619fb592df1f0cab1a60e3145a4d693baa2edd25e3ae26 1023 7
	// 5eb4ad5b053013918fddd1f121e36deb2ef102b76723e62f9602c5793f6641ec 1023 10
	//mu2 := "5eb4ad5b053013918fddd1f121e36deb2ef102b76723e62f9602c5793f6641ec" // 1023 10
	//mu2Hex, _ := hex.DecodeString(mu2)
	//mu2Hex32 := [32]byte{}
	//copy(mu2Hex32[:], mu2Hex)
	m := 1021
	n := 16
	// mu, i,j,v, y,ap
	output := pk.Verify(muHex32, leavesHashArr[:], int32(m), int32(n), vrfValue, vrfProof, authPath)
	log.Println("Verify result:", output)
	//	log.Println(tree.Leafs[1022].C)
	//	for i, _ := range tree.Leafs {
	//		// Check two leaves have same parents
	//		s := reflect.ValueOf(tree.Leafs[i].C)
	//		log.Println(s.Interface().(vrf.Message).Msg)
	//	}
}

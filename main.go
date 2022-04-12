package main

import (
	"AdvancedVRF/vrf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"strconv"

	"github.com/cbergoon/merkletree"
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
	//log.Println(tree)
	//hex.EncodeToString(pk)
	log.Println("pkv(Merkle Root):", hex.EncodeToString(pk[:]), "skv(r):", hex.EncodeToString(sk))
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
	treePath, index, _ := tree.GetMerklePath(list1[8])
	//log.Println("merklePath", merklePath)
	log.Println("Index", index)
	log.Println("TreePath", treePath)
	//0 [1] 2^10 = 1024 1023 1111 2^10 - 1024
	leavesHashArr := [1024]*[sha256.Size]byte{}

	//for i, _ := range tree.Leafs {
	//log.Println("Index", index)
	//log.Println("TreePath", treePath)
	// 0 [1] 2^10 = 1024 1023 1111 2^10 - 1024
	log.Println(tree.Leafs)
	for i, node := range tree.Leafs {
		// Check two leaves have same parents
		s := reflect.ValueOf(tree.Leafs[i].C)
		leaveHash32 := [32]byte{}
		decodeBytes, _ := hex.DecodeString(s.Interface().(vrf.Message).Msg)
		log.Println(s.Interface().(vrf.Message).Msg, "===", hex.EncodeToString(node.Hash))
		// copy(leaveHash32[:], hex.EncodeToString(node.Hash))
		copy(leaveHash32[:], decodeBytes)
		leavesHashArr[i] = &leaveHash32
	}
	log.Println(tree.Leafs[1022].Parent == tree.Leafs[1023].Parent)
	log.Println(tree.Leafs[1021].Parent == tree.Leafs[1020].Parent)

	log.Println("PK", hex.EncodeToString(pk[:]))
	log.Println("===================sk.Eval===================")
	//mu := "d084db3416cb1196b6bf7ee0e7383361096b9811bb5cb088dde7c453efd4a1ce" // 996 16
	//log.Println(leavesHashArr[1023])
	// 2de234baea20e96aeb604a008d049339c9b67da1bc64872b7703c498b383b673 996 16
	// 3754d05c0a7ea22e80491b95efac123247ed06398027090496a1abac11e423d5 996 10
	mu := "05d7a65aac6b5622dd980e8164bc2623ba1a075111993a55acb3869132475e38" // 1021 10
	muHex, _ := hex.DecodeString(mu)
	muHex32 := [32]byte{}
	copy(muHex32[:], muHex)
	i := 1021
	j := 10
	//v, pi(y,ap)
	vrfValue, vrfProof, authPath := sk.Eval(muHex32, leavesHashArr[:], int32(i), int32(j))
	log.Println("Output VRF Value", hex.EncodeToString(vrfValue))
	log.Println("Output VRF Hex Value", vrfValue)
	log.Println("Output VRF Proof", hex.EncodeToString(vrfProof))
	//get the path list1[6] 1023
	log.Println("===================pk.Verify===================")
	log.Println("=====authPath======", authPath)
	//𝑦 is 𝑥𝑖,0 in above sk.Eval
	m := 1021
	n := 10
	//mu, i,j,v, y,ap
	output := pk.Verify(muHex32, leavesHashArr[:], int32(m), int32(n), vrfValue, vrfProof, authPath)
	log.Println("Verify result:", output)

	//	log.Println(tree.Leafs[1022].C)
	//	for i, _ := range tree.Leafs {
	//		// Check two leaves have same parents
	//		s := reflect.ValueOf(tree.Leafs[i].C)
	//		log.Println(s.Interface().(vrf.Message).Msg)
	//	}

	//log.Println(authPath.Hashes)
	//log.Println(vrf.Bytes2bits(authPath.Flags))
	//log.Println("Check Hash", hex.EncodeToString(leavesHashArr[1022][:]), hex.EncodeToString(leavesHashArr[1023][:]))
	//combinedMsg1 := vrf.ConcatDigests(leavesHashArr[1022], leavesHashArr[1023])
	//rootTmp1, _ := vrf.Message{Msg: hex.EncodeToString(combinedMsg1[:])}.CalculateHash()
	//log.Println(hex.EncodeToString(combinedMsg1[:]), rootTmp1, hex.EncodeToString(rootTmp1))
	//// 4f4db5d49f026d43a70330747c843307830bf9d9b1b42e5d5e8ccf40e4a05ff4
	//combinedMsg2 := vrf.ConcatDigests(leavesHashArr[1020], leavesHashArr[1021])
	//rootTmp2, _ := vrf.Message{Msg: hex.EncodeToString(combinedMsg2[:])}.CalculateHash()
	//log.Println("rootTmp2", hex.EncodeToString(combinedMsg2[:]), hex.EncodeToString(rootTmp2))
	//combinedMsg3 := vrf.ConcatDigests(leavesHashArr[1018], leavesHashArr[1019]) // 509
	//rootTmp3, _ := vrf.Message{Msg: hex.EncodeToString(combinedMsg3[:])}.CalculateHash()
	//log.Println(hex.EncodeToString(combinedMsg3[:]), hex.EncodeToString(rootTmp3))
	//combinedMsg4 := vrf.ConcatDigests(leavesHashArr[1016], leavesHashArr[1017]) // 508
	//rootTmp4, _ := vrf.Message{Msg: hex.EncodeToString(combinedMsg4[:])}.CalculateHash()
	//log.Println(hex.EncodeToString(combinedMsg4[:]), hex.EncodeToString(rootTmp4))
	//
	//rt432 := [32]byte{}
	//copy(rt432[:], combinedMsg4[:])
	//rt332 := [32]byte{}
	//copy(rt332[:], combinedMsg3[:])
	//combinedMsg5 := vrf.ConcatDigests((*[32]byte)(combinedMsg4[:]), (*[32]byte)(combinedMsg3[:]))
	//rootTmp5, _ := vrf.Message{Msg: hex.EncodeToString(combinedMsg5[:])}.CalculateHash()
	//log.Println("combinedMsg5", hex.EncodeToString(combinedMsg5[:]), hex.EncodeToString(rootTmp5))

	// for _, hash := range authPath.Hashes {
	// 	log.Println(hex.EncodeToString(hash[:]))
	// }
	// 2022/04/07 12:31:02 03598c919b0c4b72083da7690b55a7566bb056245ef51a743333fb82d5705b58
	// 2022/04/07 12:31:02 3ca78afbdd18e9ab6b7c1ee5d908f2e5af886549ad3ced9a276ddc49582d3925
	// 2022/04/07 12:31:02 3640b54b987610170b8bf803cf385a9d92bc8ff782c7bf64f016621fe65d6329
	// 2022/04/07 12:31:02 39a5bd5fa41e330694140a72f7fbda21b32d4b15ee65e442880d5a73505fb356
	// 2022/04/07 12:31:02 23d78df0652e0eeb0f2a38f0918d07ced4937f2c4a8be90eea0949a520b0db15
	// 2022/04/07 12:31:02 0ec2c8a47b1f6327c4fe42a8911eb939f2da0b870271b2ce65bed2434b85dded
	// 2022/04/07 12:31:02 f4b10a0d204807556d6eb22468a1bc747ce3d270506c17f028bd30fe59e17ab6
	// 2022/04/07 12:31:02 4f4db5d49f026d43a70330747c843307830bf9d9b1b42e5d5e8ccf40e4a05ff4
	// 2022/04/07 12:31:02 fb8dea430a9da8c319f0bf89cac33e6b16030d57503c8f4d4bc148c5b03673ee
	// 2022/04/07 12:31:02 d084db3416cb1196b6bf7ee0e7383361096b9811bb5cb088dde7c453efd4a1ce
	// 2022/04/07 12:31:02 a7ec0cba4e85c9db65e7c67ee75dbb748d952859c1e12cfb433d3be849d19eca
	//combinedMsg := vrf.ConcatDigests((*[32]byte)(authPath.Hashes[8][:]), (*[32]byte)(authPath.Hashes[9][:])) // 1020,1021 -> 510
	//log.Println("1020+[1021] -> [510]", hex.EncodeToString(combinedMsg[:]))
	//happend := sha256.New()
	//b, err1 := happend.Write(append(authPath.Hashes[8][:], authPath.Hashes[9][:]...))
	//log.Println(b, err1)
	//log.Println("Append=====>", hex.EncodeToString(happend.Sum(nil)))
	//h := sha256.New()
	//h.Write(authPath.Hashes[8][:])
	//h.Write(authPath.Hashes[9][:])
	//var rv [sha256.Size]byte
	//copy(rv[:], h.Sum(nil))
	//log.Println("ConcatDigests=====>", hex.EncodeToString((&rv)[:]))
	//combinedMsg = vrf.ConcatDigests(combinedMsg, (*[32]byte)(authPath.Hashes[10][:])) // 510 - 511 -> 255
	//log.Println("[510] + 511 -> [255]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[7][:]), combinedMsg) // 254 - 255 -> 127
	//log.Println("254 + [255] -> [127]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[6][:]), combinedMsg) // 126 - 127 -> 63
	//log.Println("126 + [127] -> [63]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[5][:]), combinedMsg) // 62 - 63 -> 31
	//log.Println("62 + [63] -> [31]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[4][:]), combinedMsg) // 30 - 31 -> 15
	//log.Println("30 + [31] -> [15]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[3][:]), combinedMsg) // 14 - 15 -> 7
	//log.Println("14 + [15] -> [7]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[2][:]), combinedMsg) // 6 - 7 -> 3
	//log.Println("6 + [7] -> [3]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[1][:]), combinedMsg) // 2 - 3 -> 1
	//log.Println("2 + [3] -> [1]", hex.EncodeToString(combinedMsg[:]))
	//
	//combinedMsg = vrf.ConcatDigests((*[32]byte)(authPath.Hashes[0][:]), combinedMsg) // 0 - 1 -> Root'
	//
	//log.Println("0 + [1] -> [root']", hex.EncodeToString(combinedMsg[:]))
	//log.Println("PK", hex.EncodeToString(pk[:]))
	//log.Println("PK'", hex.EncodeToString(combinedMsg[:]))
}

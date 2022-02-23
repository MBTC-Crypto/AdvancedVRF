package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cbergoon/merkletree"
	"log"
	"strconv"
	"strings"
)

type Message struct {
	msg string
}
type PrivateKey []byte
type PublicKey []byte

type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

type PublicParameter struct {
	t int32
	N int32
}

func (m Message) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(m.msg)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func ParamGen(s string) (p *PublicParameter) {
	fmt.Println("Input s:", s)
	sArr := strings.Split(s, "-")
	t, _ := strconv.Atoi(sArr[0])
	N, _ := strconv.Atoi(sArr[1])
	newPP := PublicParameter{t: int32(t), N: int32(N)}
	return &newPP
}

func KeyGen(pp PublicParameter) (privkey, pubkey []byte, t *merkletree.MerkleTree) {
	r, _ := Message{msg: "AdvancedVRF"}.CalculateHash()
	var i int32 = 0
	// i [0,N-1]
	// 1. x00,x01, ... , x0t-1
	//var rootList [][]byte
	var rootList []merkletree.Content
	for i < pp.N {
		// 1. [x00,x10,x20,...,]
		xi0, _ := Message{msg: hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(0)}.CalculateHash()
		var jRoot = xi0
		var j int32 = 1
		// 2. 1,...,t-1
		for j < pp.t {
			// t-1 times
			jRoot, _ = Message{msg: hex.EncodeToString(jRoot) + hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(int(j))}.CalculateHash()
			j++
		}
		// 3. X0t, X1t,...XNt j = t
		fmt.Println(hex.EncodeToString(jRoot), hex.EncodeToString(r), strconv.Itoa(int(i)), strconv.Itoa(int(pp.t)))
		root, _ := Message{msg: hex.EncodeToString(jRoot) + hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(int(pp.t))}.CalculateHash()
		rootList = append(rootList, Message{msg: hex.EncodeToString(root)})
		i++
	}
	// TODO Build Merkle tree using
	// create a NEW Merkle Tree from the list of content
	tree, err := merkletree.NewTree(rootList)
	if err != nil {
		log.Fatal(err)
	}
	mr := tree.MerkleRoot()
	//log.Println("Merkle Root:", hex.EncodeToString(mr), "r:", hex.EncodeToString(r))

	return mr, r, tree
}

// Eval return VRF value and its accompanying proof pi
func Eval(sk PrivateKey, pp PublicParameter) (vrfValue, proof []byte) {
	var i int32 = 0
	for i < pp.N {
		// for r = sk
		xi0, _ := Message{msg: hex.EncodeToString(sk) + strconv.Itoa(int(i))}.CalculateHash()
		fmt.Println(xi0)
		i++
	}
	return []byte("test"), []byte("test")
}

func (pkBytes PublicKey) Verify(msg, index, vrfValue, proof []byte) bool {
	return true
}

func (m Message) Equals(other merkletree.Content) (bool, error) {
	return m.msg == other.(Message).msg, nil
}

func main() {
	fmt.Println("===================ParamGen===================")
	pg := ParamGen("16-1024")
	fmt.Println("PG.N", pg.N)
	fmt.Println("PG.t", pg.t)

	fmt.Println("===================KeyGen===================")
	pp := PublicParameter{
		t: pg.t,
		N: pg.N,
	}
	pk, sk, tree := KeyGen(pp)
	//hex.EncodeToString(pk)
	log.Println("Merkle Root:", hex.EncodeToString(pk), "r:", hex.EncodeToString(sk))
	vt, err := tree.VerifyTree()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verify Tree:", vt)
	// verify the entire tree is valid
	var list1 []merkletree.Content
	rStr := "989eb61064c3452618e3c58c3a4ccac5af4e261a38e34563f4149de121bda639"
	v1t, _ := Message{msg: "91e8531b46fe71c2391c0a0a72450b6bf7b0d1dcc5d142cab1af5c355535358e" + rStr + strconv.Itoa(int(980)) + strconv.Itoa(16)}.CalculateHash()
	v1f1, _ := Message{msg: "37514f5173096f56d9621c2685a165c6548d6cd5058d0adfa08cc7a17b4a8a31" + rStr + strconv.Itoa(int(980)) + strconv.Itoa(16)}.CalculateHash()
	v1f2, _ := Message{msg: "91e8531b46fe71c2391c0a0a72450b6bf7b0d1dcc5d142cab1af5c355535358e" + rStr + strconv.Itoa(int(981)) + strconv.Itoa(16)}.CalculateHash()

	v2t, _ := Message{msg: "76dacb6f8e19b8dc22c67c152c0f8a40a2323bbfe54a13360727029ec16d6f81" + rStr + strconv.Itoa(int(1018)) + strconv.Itoa(16)}.CalculateHash()
	v2f1, _ := Message{msg: "2e8a2554336e4ba966b6b352a9a8e320edf45e6586572576c37627d70c0e7559" + rStr + strconv.Itoa(int(1018)) + strconv.Itoa(16)}.CalculateHash()
	v2f2, _ := Message{msg: "37514f5173096f56d9621c2685a165c6548d6cd5058d0adfa08cc7a17b4a8a31" + rStr + strconv.Itoa(int(1019)) + strconv.Itoa(16)}.CalculateHash()

	v3t, _ := Message{msg: "e8511fb8e1f132ba214b9354862c552091eb55a5bc04c96e7a77bdd2643c4699" + rStr + strconv.Itoa(int(1023)) + strconv.Itoa(16)}.CalculateHash()
	v3f1, _ := Message{msg: "064143d2a8747c6459374d1133aa9df546953bfcb3e4286cb3bbcc657982d822" + rStr + strconv.Itoa(int(1024)) + strconv.Itoa(16)}.CalculateHash()
	v3f2, _ := Message{msg: "064143d2a8747c6459374d1133aa9df546953bfcb3e4286cb3bbcc657982d822" + rStr + strconv.Itoa(int(1023)) + strconv.Itoa(16)}.CalculateHash()

	list1 = append(list1, Message{msg: hex.EncodeToString(v1t)})  // true
	list1 = append(list1, Message{msg: hex.EncodeToString(v1f1)}) // false
	list1 = append(list1, Message{msg: hex.EncodeToString(v1f2)}) // false

	list1 = append(list1, Message{msg: hex.EncodeToString(v2t)})  // true
	list1 = append(list1, Message{msg: hex.EncodeToString(v2f1)}) // false
	list1 = append(list1, Message{msg: hex.EncodeToString(v2f2)}) // false

	list1 = append(list1, Message{msg: hex.EncodeToString(v3t)})  // true
	list1 = append(list1, Message{msg: hex.EncodeToString(v3f1)}) // false
	list1 = append(list1, Message{msg: hex.EncodeToString(v3f2)}) // false
	//3fa148e3af80065ae1d5dac200b9ea1c41374601c0a97a1441d3bd05db295574 989eb61064c3452618e3c58c3a4ccac5af4e261a38e34563f4149de121bda639 15 16
	v15t, _ := Message{msg: "3fa148e3af80065ae1d5dac200b9ea1c41374601c0a97a1441d3bd05db295574" + rStr + strconv.Itoa(int(15)) + strconv.Itoa(16)}.CalculateHash()
	list1 = append(list1, Message{msg: hex.EncodeToString(v15t)}) // false

	// TODO Can test with rootList
	for _, message := range list1 {
		vc, err := tree.VerifyContent(message)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Verify Content:", vc)
	}
	fmt.Println("===================Eval===================")
	//vrfValue, proof := Eval(sk, pp)
	//fmt.Println(vrfValue, proof)
	// get the path list1[6] 1023
	merklePath, index, err := tree.GetMerklePath(list1[0])
	fmt.Println(merklePath, index, err)

}

type MerkleTree struct {
	RootNode *MerkleNode
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	mNode := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		mNode.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		mNode.Data = hash[:]
	}

	mNode.Left = left
	mNode.Right = right

	return &mNode
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode

	if len(data)%2 != 0 {
		data = append(data, data[len(data)-1])
	}

	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, *node)
	}

	for i := 0; i < len(data)/2; i++ {
		var newLevel []MerkleNode

		for j := 0; j < len(nodes); j += 2 {
			node := NewMerkleNode(&nodes[j], &nodes[j+1], nil)
			newLevel = append(newLevel, *node)
		}

		nodes = newLevel
	}

	mTree := MerkleTree{&nodes[0]}

	return &mTree
}

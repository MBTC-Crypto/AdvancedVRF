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
	r   []byte
	i   int32
	j   int32
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
func (m Message) Hash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(m.msg)); err != nil {
		return nil, err
	}
	if _, err := h.Write(m.r); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte(string(m.i))); err != nil {
		return nil, err
	}
	if _, err := h.Write([]byte(string(m.j))); err != nil {
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
	//r := make([]byte, 256/8)
	//rand.Read(r)
	r, _ := hex.DecodeString("bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb")
	var i int32 = 0
	var j int32 = 1
	// i [0,N-1]
	// 1. x00,x01, ... , x0t-1
	var xis [][]byte
	//var rootList [][]byte
	var rootList []merkletree.Content
	for ; i < pp.N; i++ {
		m := Message{msg: "AdvancedVRF" + hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(int(j))}
		xi0, _ := m.Hash()
		xis = append(xis, xi0)
		var jRoot = xi0
		for ; j < pp.t; j++ {
			jRoot, _ = Message{msg: hex.EncodeToString(jRoot) + hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(int(j))}.Hash()
		}
		// X0t, X1t,...XNt j = t
		//fmt.Println(i, pp.t)
		fmt.Println(hex.EncodeToString(jRoot), hex.EncodeToString(r), strconv.Itoa(int(i)), strconv.Itoa(int(pp.t)))
		rootList = append(rootList, Message{msg: hex.EncodeToString(jRoot) + hex.EncodeToString(r) + strconv.Itoa(int(i)) + strconv.Itoa(int(pp.t))})
	}
	// TODO Build Merkle tree using
	// create a NEW Merkle Tree from the list of content
	tree, err := merkletree.NewTree(rootList)
	if err != nil {
		log.Fatal(err)
	}
	mr := tree.MerkleRoot()
	log.Println("Merkle Root:", hex.EncodeToString(mr), "r:", hex.EncodeToString(r))

	return mr, r, tree
}

// Eval return VRF value and its accompanying proof pi
func (sk PrivateKey) Eval(msg Message) (vrfValue, proof []byte) {
	//var i int32 = 0
	//for i < msg.i {
	//	// for r = sk
	//	xi, _ := Message{msg: "AdvancedVRF", r: sk, i: i, j: 0}.Hash()
	//	y =
	//	i++
	//}
	return []byte("test"), []byte("test")
}

func (pkBytes PublicKey) Verify(msg, index, vrfValue, proof []byte) bool {
	return true
}

func (m Message) Equals(other merkletree.Content) (bool, error) {
	return m.msg == other.(Message).msg, nil
}

func main() {
	fmt.Println("======")
	//fmt.Println(t)
	pg := ParamGen("16-1024")
	fmt.Println("PG.N", pg.N)
	fmt.Println("PG.t", pg.t)
	pp := PublicParameter{
		t: 16,
		N: 1024,
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

	list1 = append(list1, Message{msg: "1964f409d1e4fd3ea2691677c39991baefce762ca73051f7c4b0a57f3d2489ca" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(980)) + strconv.Itoa(16)})
	list1 = append(list1, Message{msg: "1964f409d1e4fd3ea2691677c39991baefce762ca73051f7c4b0a57f3d2489ca" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(981)) + strconv.Itoa(16)})
	list1 = append(list1, Message{msg: "ffa50a0426b85b7db119aaab7e828198f2223c9002c4e58965264357c664cc21" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(1018)) + strconv.Itoa(16)})
	list1 = append(list1, Message{msg: "ffa50a0426b85b7db119aaab7e828198f2223c9002c4e58965264357c664cc21" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(1019)) + strconv.Itoa(16)})
	list1 = append(list1, Message{msg: "fdd18f57dc33ec081ed5a74c14e1562c9a74ebb09534c3c6707ee64e756c183b" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(1023)) + strconv.Itoa(16)})
	list1 = append(list1, Message{msg: "fdd18f57dc33ec081ed5a74c14e1562c9a74ebb09534c3c6707ee64e756c183b" +
		"bf17624842eedc4f4c8789dd4e958903b36edc29f038057fbc3ca537931ca9bb" +
		strconv.Itoa(int(1023)) + strconv.Itoa(15)})
	// TODO Can test with rootList
	vc, err := tree.VerifyContent(list1[3])
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verify Content:", vc)
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

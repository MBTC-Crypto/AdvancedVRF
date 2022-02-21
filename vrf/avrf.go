package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cbergoon/merkletree"
	"log"
)

type Message struct {
	msg string
}
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

func (m Message) CalculateHash() ([]byte, error) {
	h := sha256.New()
	//sha256.Sum256([]byte(m.msg))
	if _, err := h.Write([]byte(m.msg)); err != nil {
		return nil, err
	}
	//sk := "mysecret"
	//h = hmac.New(sha256.New, []byte(sk))
	//h.Write([]byte(m.msg))
	//sha := hex.EncodeToString(h.Sum(nil))
	//return []byte(sha), nil
	return h.Sum(nil), nil
}

func (m Message) Equals(other merkletree.Content) (bool, error) {
	return m.msg == other.(Message).msg, nil
}

func main() {
	fmt.Println("======")
	var list1 []merkletree.Content
	var list2 []merkletree.Content

	list2 = append(list2, Message{"Wayne"})
	list1 = append(list1, Message{"A"})
	list1 = append(list1, Message{"B"})
	list1 = append(list1, Message{"C"})
	list1 = append(list1, Message{"D"})
	list1 = append(list1, Message{"E"})
	// create a NEW Merkle Tree from the list of content
	t, err := merkletree.NewTree(list1)
	if err != nil {
		log.Fatal(err)
	}

	// Get the merkel root of the tree
	mr := t.MerkleRoot()
	log.Println("Merkle Root:", hex.EncodeToString(mr))

	// verify the entire tree is valid
	vt, err := t.VerifyTree()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verify Tree:", vt)
	// verify the entire tree is valid
	vc, err := t.VerifyContent(list1[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verify Content:", vc)

	// String representation
	fmt.Println(t)
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

package vrf

import (
	"crypto/sha256"
	"github.com/cbergoon/merkletree"
	"golang.org/x/crypto/sha3"
)

type Message struct {
	Msg string
}

func (m Message) Equals(other merkletree.Content) (bool, error) {
	return m.Msg == other.(Message).Msg, nil
}

type PrivateKey []byte
type PublicKey []byte

type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

type PublicParameter struct {
	T int32
	N int32
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

// Branch is a cooked merkle authentication path that can be transmitted
// over a wire and can be verified on the other end.
type Branch struct {
	NumLeaves uint32              // Nuber of leaves
	Hashes    [][sha256.Size]byte // Merkle branch
	Flags     []byte              // Bitmap of merkle tree
}

// MerkleBranch holds intermediate state while validating a merkle path.
type MerkleBranch struct {
	numLeaves uint32
	bitsUsed  uint32
	hashUsed  uint32
	hashes    [][sha256.Size]byte
	inHashes  [][sha256.Size]byte
	bits      []byte
}

// AuthPath is used to house intermediate information needed to generate a Branch.
type AuthPath struct {
	numLeaves   uint32
	matchedBits []byte
	bits        []byte
	allHashes   []*[sha256.Size]byte
	finalHashes []*[sha256.Size]byte
}

type Xof struct {
	sh sha3.ShakeHash
	// key is here to not make excess garbage during repeated calls
	// to XORKeyStream.
	key []byte
}

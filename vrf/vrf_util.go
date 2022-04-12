package vrf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"math"
)

func (m Message) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(m.Msg)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (m Message) CalculateShake() ([]byte, error) {
	buf := []byte(m.Msg)
	h := make([]byte, len(buf))
	sha3.ShakeSum256(h, buf)
	return h, nil
}

func ConcatDigests(hashes ...*[sha256.Size]byte) *[sha256.Size]byte {
	h := sha256.New()
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var rv [sha256.Size]byte
	copy(rv[:], h.Sum(nil))
	return &rv
}

func ComputeMerkleRoot(leaveHashes [][32]byte) [32]byte {
	numOfLeaves := len(leaveHashes)
	log.Println("Num of Leaves:", numOfLeaves)
	index := 0
	//var leavesHashArr []*[sha256.Size]byte
	tmpLen := numOfLeaves / 2
	tempLeavesHashArr := make([][32]byte, tmpLen)
	for i, _ := range leaveHashes {
		if index < numOfLeaves {
			intermediateHash := sha256.Sum256(append(leaveHashes[index][:], leaveHashes[index+1][:]...))
			log.Println(i, index, index+1, numOfLeaves, intermediateHash, hex.EncodeToString(intermediateHash[:]))
			tempLeavesHashArr[i] = intermediateHash
			if numOfLeaves == 2 {
				return intermediateHash
			}
			index += 2
		} else {
			log.Println("Completed Round", i)
			break
		}
	}
	return ComputeMerkleRoot(tempLeavesHashArr)
}

// calcTreeWidth calculates the width of the tree at a given height.
// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func calcTreeWidth(num, height uint32) uint32 {
	return (num + (1 << height) - 1) >> height
}

func CalculateAuthPath(leaves []*[sha256.Size]byte, hash *[sha256.Size]byte) *Branch {
	numLeaves := uint32(len(leaves))
	if numLeaves == 0 {
		return nil
	}
	ap := AuthPath{
		numLeaves:   numLeaves,
		matchedBits: make([]byte, 0, numLeaves),
		allHashes:   leaves,
	}

	for _, v := range ap.allHashes {
		if v != nil && *v == *hash {
			ap.matchedBits = append(ap.matchedBits, 0x01)
		} else {
			ap.matchedBits = append(ap.matchedBits, 0x00)
		}
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for calcTreeWidth(ap.numLeaves, height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	ap.traverseAndBuild(height, 0)

	// Create merkle branch.
	mb := &Branch{
		NumLeaves: numLeaves,
		Hashes:    make([][sha256.Size]byte, 0, len(ap.finalHashes)),
		Flags:     make([]byte, (len(ap.bits)+7)/8),
	}

	// Create bitmap.
	for i := uint32(0); i < uint32(len(ap.bits)); i++ {
		mb.Flags[i/8] |= ap.bits[i] << (i % 8)
	}

	// Copy hashes
	for _, hash := range ap.finalHashes {
		mb.Hashes = append(mb.Hashes, *hash)
	}

	return mb
}

// VerifyAuthPath takes a Branch and ensures that it is a valid tree.
func VerifyAuthPath(mb *Branch) (*[sha256.Size]byte, error) {
	if mb.NumLeaves == 0 || len(mb.Hashes) == 0 {
		return nil, errors.New("empty merkle branch")
	}

	m := &MerkleBranch{
		bits:      bytes2bits(mb.Flags),
		inHashes:  mb.Hashes,
		numLeaves: mb.NumLeaves,
	}

	height := uint32(math.Ceil(math.Log2(float64(mb.NumLeaves))))
	merkleRoot, err := m.extract(height, 0)
	if err != nil {
		return nil, err
	}

	// Validate that we consumed all bits and bobs.
	flagByte := int(math.Floor(float64(m.bitsUsed / 8)))
	if flagByte+1 < len(mb.Flags) && mb.Flags[flagByte] > 1<<m.bitsUsed%8 {
		return nil, fmt.Errorf("did not consume all flag bits")
	}

	if m.hashUsed != uint32(len(mb.Hashes)) {
		return nil, fmt.Errorf("did not consume all hashes")
	}

	return merkleRoot, nil
}

// extract recurse over the merkleBranch and returns the merkle root.
func (m *MerkleBranch) extract(height, pos uint32) (*[sha256.Size]byte, error) {
	parentOfMatch := m.bits[m.bitsUsed]
	m.bitsUsed++
	if height == 0 || parentOfMatch == 0 {
		hash := m.inHashes[m.hashUsed]
		m.hashUsed++
		if height == 0 && parentOfMatch == 1 {
			m.hashes = append(m.hashes, hash)
		}
		return &hash, nil
	}

	left, err := m.extract(height-1, pos*2)
	if err != nil {
		return nil, err
	}
	if pos*2+1 < calcTreeWidth(m.numLeaves, height-1) {
		right, err := m.extract(height-1, pos*2+1)
		if err != nil {
			return nil, err
		}
		if *left == *right {
			return nil, fmt.Errorf("equivalent hashes")
		}

		return ConcatDigests(left, right), nil
	}

	return ConcatDigests(left, left), nil
}

// bytes2bits converts merkle tree bitmap into a byte array.
func bytes2bits(b []byte) []byte {
	bits := make([]byte, 0, len(b)*8)
	for i := 0; i < len(b); i++ {
		for j := uint(0); j < 8; j++ {
			bits = append(bits, (b[i]>>j)&0x01)
		}
	}

	return bits
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.
func (a *AuthPath) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < a.numLeaves; i++ {
		isParent |= a.matchedBits[i]
	}
	a.bits = append(a.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		a.finalHashes = append(a.finalHashes, a.calcHash(height, pos))
		return
	}

	// Descend into the left child and process its sub-tree.
	a.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		a.traverseAndBuild(height-1, pos*2+1)
	}
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (a *AuthPath) calcHash(height, pos uint32) *[sha256.Size]byte {
	if height == 0 {
		return a.allHashes[pos]
	}

	var right *[sha256.Size]byte
	left := a.calcHash(height-1, pos*2)
	if pos*2+1 < calcTreeWidth(a.numLeaves, height-1) {
		right = a.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	return ConcatDigests(left, right)
}

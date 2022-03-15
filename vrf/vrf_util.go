package vrf

import "crypto/sha256"

func (m Message) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(m.Msg)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
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

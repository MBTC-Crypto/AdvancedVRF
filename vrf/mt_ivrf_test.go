package vrf

import (
	"crypto/sha256"
	"github.com/cbergoon/merkletree"
	"reflect"
	"testing"
)

func TestKeyGen(t *testing.T) {
	type args struct {
		pp PublicParameter
	}
	var tests []struct {
		name        string
		args        args
		wantPubkey  PublicKey
		wantPrivkey PrivateKey
		wantT       *merkletree.MerkleTree
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPubkey, gotPrivkey, gotT := KeyGen(tt.args.pp)
			if !reflect.DeepEqual(gotPubkey, tt.wantPubkey) {
				t.Errorf("KeyGen() gotPubkey = %v, want %v", gotPubkey, tt.wantPubkey)
			}
			if !reflect.DeepEqual(gotPrivkey, tt.wantPrivkey) {
				t.Errorf("KeyGen() gotPrivkey = %v, want %v", gotPrivkey, tt.wantPrivkey)
			}
			if !reflect.DeepEqual(gotT, tt.wantT) {
				t.Errorf("KeyGen() gotT = %v, want %v", gotT, tt.wantT)
			}
		})
	}
}

func TestParamGen(t *testing.T) {
	type args struct {
		s string
	}
	var tests []struct {
		name  string
		args  args
		wantP *PublicParameter
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotP := ParamGen(tt.args.s); !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("ParamGen() = %v, want %v", gotP, tt.wantP)
			}
		})
	}
}

func TestPrivateKey_Eval(t *testing.T) {
	type args struct {
		mu          [32]byte
		leaveHashes []*[sha256.Size]byte
		i           int32
		j           int32
	}
	var tests []struct {
		name         string
		sk           PrivateKey
		args         args
		wantVrfValue []byte
		wantVrfProof []byte
		wantMb       *Branch
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVrfValue, gotVrfProof, gotMb := tt.sk.Eval(tt.args.mu, tt.args.leaveHashes, tt.args.i, tt.args.j)
			if !reflect.DeepEqual(gotVrfValue, tt.wantVrfValue) {
				t.Errorf("Eval() gotVrfValue = %v, want %v", gotVrfValue, tt.wantVrfValue)
			}
			if !reflect.DeepEqual(gotVrfProof, tt.wantVrfProof) {
				t.Errorf("Eval() gotVrfProof = %v, want %v", gotVrfProof, tt.wantVrfProof)
			}
			if !reflect.DeepEqual(gotMb, tt.wantMb) {
				t.Errorf("Eval() gotMb = %v, want %v", gotMb, tt.wantMb)
			}
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	type args struct {
		mu          [32]byte
		leaveHashes []*[sha256.Size]byte
		i           int32
		j           int32
		vrfValue    []byte
		vrfProof    []byte
		mb          *Branch
	}
	var tests []struct {
		name string
		pk   PublicKey
		args args
		want int
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pk.Verify(tt.args.mu, tt.args.leaveHashes, tt.args.i, tt.args.j, tt.args.vrfValue, tt.args.vrfProof, tt.args.mb); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

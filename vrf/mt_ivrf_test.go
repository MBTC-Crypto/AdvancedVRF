package vrf

import (
	"crypto/sha256"
	"reflect"
	"testing"
)

func TestKeyGen(t *testing.T) {
	tests := []struct {
		name            string
		wantPubkey      PublicKey
		wantPrivkey     PrivateKey
		wantLeaveHashes [][]byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPubkey, gotPrivkey, gotLeaveHashes := KeyGen()
			if !reflect.DeepEqual(gotPubkey, tt.wantPubkey) {
				t.Errorf("KeyGen() gotPubkey = %v, want %v", gotPubkey, tt.wantPubkey)
			}
			if !reflect.DeepEqual(gotPrivkey, tt.wantPrivkey) {
				t.Errorf("KeyGen() gotPrivkey = %v, want %v", gotPrivkey, tt.wantPrivkey)
			}
			if !reflect.DeepEqual(gotLeaveHashes, tt.wantLeaveHashes) {
				t.Errorf("KeyGen() gotLeaveHashes = %v, want %v", gotLeaveHashes, tt.wantLeaveHashes)
			}
		})
	}
}

func TestParamGen(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name  string
		args  args
		wantP *PublicParameter
	}{
		// TODO: Add test cases.
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
	tests := []struct {
		name      string
		sk        PrivateKey
		args      args
		wantProof VrfProof
		wantOk    bool
		wantAp    *Branch
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProof, gotOk, gotAp := tt.sk.Eval(tt.args.mu, tt.args.leaveHashes, tt.args.i, tt.args.j)
			if !reflect.DeepEqual(gotProof, tt.wantProof) {
				t.Errorf("Eval() gotProof = %v, want %v", gotProof, tt.wantProof)
			}
			if gotOk != tt.wantOk {
				t.Errorf("Eval() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotAp, tt.wantAp) {
				t.Errorf("Eval() gotAp = %v, want %v", gotAp, tt.wantAp)
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
		proof       VrfProof
		ap          *Branch
	}
	tests := []struct {
		name string
		pk   PublicKey
		args args
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.pk.Verify(tt.args.mu, tt.args.leaveHashes, tt.args.i, tt.args.j, tt.args.proof, tt.args.ap); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

package token

import (
	"testing"
)

func TestMintShape(t *testing.T) {
	id, err := NewMint(22)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(id, 22) {
		t.Fatalf("minted id %q fails ValidID", id)
	}
	if !ValidID("0AzZ22", 6) {
		t.Fatal("valid id rejected")
	}
	for _, bad := range []string{"", "short", "with space0000000000", "with/slash00000000", "ünïcode0000000000000"} {
		if ValidID(bad, 22) {
			t.Fatalf("invalid id accepted: %q", bad)
		}
	}
}

func TestMintUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id, err := NewMint(22)
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate id after %d draws", i)
		}
		seen[id] = true
	}
}

func TestHashTokenIsOneWay(t *testing.T) {
	h1 := HashToken("manager-token-value")
	h2 := HashToken("manager-token-value")
	if h1 != h2 {
		t.Fatal("same token hashed differently")
	}
	if h1 == "manager-token-value" {
		t.Fatal("hash equals input")
	}
	if HashToken("different") == h1 {
		t.Fatal("collision between different tokens")
	}
}

func TestPartTokens(t *testing.T) {
	secret := []byte("session-secret")
	tok := PartToken(secret, "sess1", 3)
	if !VerifyPartToken(secret, "sess1", 3, tok) {
		t.Fatal("valid part token rejected")
	}
	if VerifyPartToken(secret, "sess1", 4, tok) {
		t.Fatal("part token accepted for the wrong part number")
	}
	if VerifyPartToken(secret, "sess2", 3, tok) {
		t.Fatal("part token accepted for the wrong session")
	}
	if VerifyPartToken([]byte("other"), "sess1", 3, tok) {
		t.Fatal("part token accepted with the wrong secret")
	}
}

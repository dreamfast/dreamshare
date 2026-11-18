// Package token mints the capability identifiers. Ids come from crypto/rand
// only, the depguard rule enforces that repo wide.
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewMint returns n characters of uniform base62 from the CSPRNG, 22
// characters is the id length used for share and file capability tokens.
// Modulo reduction would bias the last bits away, so values above the last
// whole multiple of 62 are rejected and redrawn.
func NewMint(n int) (string, error) {
	limit := 256 / len(alphabet) * len(alphabet)
	var b strings.Builder
	b.Grow(n)
	for b.Len() < n {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		for _, v := range raw {
			if int(v) < limit {
				b.WriteByte(alphabet[int(v)%len(alphabet)])
				if b.Len() == n {
					break
				}
			}
		}
	}
	return b.String(), nil
}

// ValidID accepts only the mint alphabet and length, so a client can never
// smuggle a crafted id into a lookup.
func ValidID(s string, wantLen int) bool {
	if len(s) != wantLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !ok {
			return false
		}
	}
	return true
}

// HashToken is how tokens are stored when they only need to be compared,
// never read back. A database leak grants no rights.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PartToken issues the look ahead upload token for one part number. The
// secret is per upload session, the server hands out the next few tokens per
// response so flow control costs no session state.
func PartToken(secret []byte, sessionID string, partNumber int) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "part:%s:%d", sessionID, partNumber)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyPartToken checks a part token in constant time.
func VerifyPartToken(secret []byte, sessionID string, partNumber int, given string) bool {
	want := PartToken(secret, sessionID, partNumber)
	return hmac.Equal([]byte(want), []byte(given))
}

// ObjectKey builds the storage key for one file. Keys are server generated,
// unique per file and never derived from a filename, so a user string never
// becomes a path and keys are never reused.
func ObjectKey(ym string, fileID string) string {
	return "f/" + ym + "/" + fileID
}

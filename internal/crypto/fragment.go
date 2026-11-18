package crypto

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// The whole URL fragment is the key, exactly like the reference prototype:
// 32 random bytes, URL safe base64, padding stripped, 43 characters. No
// prefix, no k= marker. A fragment that is not exactly 43 canonical
// characters is a malformed link, hard fail, because a wrong length import
// is a quiet support ticket rather than a user error.

const FragmentLen = 43 // base64url of 32 bytes without padding

// EncodeFragmentKey renders a master key as the URL fragment payload.
func EncodeFragmentKey(master []byte) (string, error) {
	if len(master) != KeySize {
		return "", fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(master))
	}
	return base64.RawURLEncoding.EncodeToString(master), nil
}

// DecodeFragmentKey parses a fragment payload back into a master key. It
// rejects the wrong length, invalid characters and non canonical trailing
// bits, so a truncated or mangled link never becomes a wrong key.
func DecodeFragmentKey(fragment string) ([]byte, error) {
	if len(fragment) != FragmentLen {
		return nil, fmt.Errorf("link key must be %d characters, got %d", FragmentLen, len(fragment))
	}
	if strings.ContainsAny(fragment, "+/=") {
		return nil, fmt.Errorf("link key is not URL safe base64")
	}
	master, err := base64.RawURLEncoding.DecodeString(fragment)
	if err != nil {
		return nil, fmt.Errorf("link key is not valid base64url: %w", err)
	}
	if len(master) != KeySize {
		return nil, fmt.Errorf("link key must decode to %d bytes, got %d", KeySize, len(master))
	}
	// re-encode and compare catches non canonical trailing bits, which some
	// forgiving decoders silently accept
	if re, _ := EncodeFragmentKey(master); re != fragment {
		return nil, fmt.Errorf("link key is not canonical base64url")
	}
	return master, nil
}

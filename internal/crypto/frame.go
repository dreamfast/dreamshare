// Package crypto is the Go reference implementation of the share frame
// format. The browser does the real sealing and opening, this package exists
// so the format is pinned by interop fixtures and tests on both sides, and so
// operational tooling can inspect a blob when debugging.
//
// ds1 format, one frame:
//
//	version(1) = 0x01
//	nonce(12)  = 4 byte per-subkey random prefix + 8 byte big endian frame counter
//	body       = AES-256-GCM ciphertext, plaintext length + 16 byte tag
//
// The last frame of an object may be short, its plaintext length is the frame
// length minus 29. AAD binds the format version, share id, purpose, frame
// index and last-frame flag, so a frame spliced from another object, share or
// purpose fails authentication.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Format constants. Every one of these is duplicated in the TypeScript twin
// and asserted against the interop fixtures, changing one side alone breaks
// the other loudly.
const (
	FormatVersion     byte   = 0x01
	FormatName        string = "ds1"
	FramePlaintextMax        = 1 << 20 // 1 MiB
	HeaderSize               = 13      // version + nonce
	TagSize                  = 16      // GCM tag
	FrameOverhead            = HeaderSize + TagSize
)

// KeySize is the master key and every subkey length, 256 bits.
const KeySize = 32

// NoncePrefixSize and CounterSize make up the 12 byte GCM nonce.
const (
	NoncePrefixSize = 4
	CounterSize     = 8
	NonceSize       = NoncePrefixSize + CounterSize
)

// ErrBadFrame wraps every open failure so callers can distinguish corruption
// from misuse without string matching.
var ErrBadFrame = errors.New("bad frame")

// SubkeyInfo is the HKDF info string for a purpose. File subkeys bind the
// file id so one master key over many files never reuses a key across them.
func SubkeyInfo(purpose, id string) string {
	if id == "" {
		return "dreamshare:" + purpose
	}
	return "dreamshare:" + purpose + ":" + id
}

// Purposes are the fixed AAD labels. Adding one is a format change.
const (
	PurposeFile     = "file"
	PurposeManifest = "manifest"
	PurposeCheck    = "check"
	PurposeTitle    = "title"
)

// DeriveSubkey expands the master key into one 32 byte subkey. Empty salt,
// SHA-256, the info string carries the separation.
func DeriveSubkey(master []byte, info string) ([]byte, error) {
	if len(master) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(master))
	}
	out, err := hkdf.Key(sha256.New, master, nil, info, KeySize)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AAD builds the authenticated additional data for one frame. Canonical
// encoding, NUL separated, ids never contain NUL:
//
//	"ds1" 0x00 shareID 0x00 purpose 0x00 uint64be(index) lastFlag
func AAD(shareID, purpose string, index uint64, last bool) []byte {
	out := make([]byte, 0, 3+1+len(shareID)+1+len(purpose)+1+8+1)
	out = append(out, FormatName...)
	out = append(out, 0)
	out = append(out, shareID...)
	out = append(out, 0)
	out = append(out, purpose...)
	out = append(out, 0)
	var idx [CounterSize]byte
	binary.BigEndian.PutUint64(idx[:], index)
	out = append(out, idx[:]...)
	if last {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// NewNoncePrefix returns a fresh 4 byte prefix from the system CSPRNG. One
// per subkey per object, paired with the counter it makes nonce reuse
// impossible by construction.
func NewNoncePrefix() ([]byte, error) {
	p := make([]byte, NoncePrefixSize)
	if _, err := rand.Read(p); err != nil {
		return nil, err
	}
	return p, nil
}

// BuildNonce joins a prefix and counter into the 12 byte GCM nonce.
func BuildNonce(prefix []byte, index uint64) ([]byte, error) {
	if len(prefix) != NoncePrefixSize {
		return nil, fmt.Errorf("nonce prefix must be %d bytes, got %d", NoncePrefixSize, len(prefix))
	}
	n := make([]byte, NonceSize)
	copy(n, prefix)
	binary.BigEndian.PutUint64(n[NoncePrefixSize:], index)
	return n, nil
}

// SealFrame seals one frame. index is the frame counter across the whole
// object, not the chunk.
func SealFrame(subkey, noncePrefix []byte, index uint64, plaintext, aad []byte) ([]byte, error) {
	if len(subkey) != KeySize {
		return nil, fmt.Errorf("%w: subkey must be %d bytes, got %d", ErrBadFrame, KeySize, len(subkey))
	}
	nonce, err := BuildNonce(noncePrefix, index)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	frame[0] = FormatVersion
	copy(frame[1:], nonce)
	// Seal appends to dst and returns the result, assign it back or the
	// ciphertext is silently dropped
	frame = gcm.Seal(frame[:HeaderSize], nonce, plaintext, aad)
	return frame, nil
}

// OpenFrame authenticates and opens one frame.
func OpenFrame(subkey, frame, aad []byte) ([]byte, error) {
	if len(subkey) != KeySize {
		return nil, fmt.Errorf("%w: subkey must be %d bytes, got %d", ErrBadFrame, KeySize, len(subkey))
	}
	if len(frame) < HeaderSize+1+TagSize {
		// a 1 byte plaintext is the smallest legal frame
		return nil, fmt.Errorf("%w: frame too short, %d bytes", ErrBadFrame, len(frame))
	}
	if frame[0] != FormatVersion {
		return nil, fmt.Errorf("%w: unknown frame version %d", ErrBadFrame, frame[0])
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := frame[1:HeaderSize]
	pt, err := gcm.Open(nil, nonce, frame[HeaderSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadFrame, err)
	}
	return pt, nil
}

// FrameIndex returns the frame counter embedded in a frame nonce, so a
// streaming opener can assert ordering without trusting it for security.
func FrameIndex(frame []byte) (uint64, error) {
	if len(frame) < HeaderSize {
		return 0, fmt.Errorf("%w: frame too short", ErrBadFrame)
	}
	return binary.BigEndian.Uint64(frame[1+NoncePrefixSize : HeaderSize]), nil
}

// SealStream seals a whole buffer into frames of at most FramePlaintextMax,
// starting at startIndex. It is the in-memory shape of what the browser does
// per chunk, used by tests and fixture generation.
func SealStream(subkey, noncePrefix []byte, startIndex uint64, plaintext []byte, aad func(index uint64, last bool) []byte) ([]byte, error) {
	var out []byte
	index := startIndex
	for off := 0; off < len(plaintext); off += FramePlaintextMax {
		end := off + FramePlaintextMax
		if end > len(plaintext) {
			end = len(plaintext)
		}
		last := end == len(plaintext)
		frame, err := SealFrame(subkey, noncePrefix, index, plaintext[off:end], aad(index, last))
		if err != nil {
			return nil, err
		}
		out = append(out, frame...)
		index++
	}
	return out, nil
}

// OpenStream opens concatenated frames, verifying each frame's counter runs
// contiguously from startIndex and the last frame carries the last flag.
func OpenStream(subkey, stream []byte, startIndex uint64, aad func(index uint64, last bool) []byte) ([]byte, error) {
	var out []byte
	index := startIndex
	for len(stream) > 0 {
		// frames are stride sized except the last, so the split is exact by
		// construction and the tag check catches any deviation
		var frame []byte
		if len(stream) > FramePlaintextMax+FrameOverhead {
			frame = stream[:FramePlaintextMax+FrameOverhead]
		} else {
			frame = stream
		}
		pt, err := OpenFrame(subkey, frame, aad(index, len(stream) == len(frame)))
		if err != nil {
			// the split guess was wrong only when a partial frame was tried
			// mid-stream, which cannot happen by construction above
			return nil, err
		}
		gotIndex, err := FrameIndex(frame)
		if err != nil {
			return nil, err
		}
		if gotIndex != index {
			return nil, fmt.Errorf("%w: frame out of order, got counter %d want %d", ErrBadFrame, gotIndex, index)
		}
		out = append(out, pt...)
		stream = stream[len(frame):]
		index++
	}
	return out, nil
}

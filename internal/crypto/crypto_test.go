package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func mustSubkey(t *testing.T, master []byte, info string) []byte {
	t.Helper()
	k, err := DeriveSubkey(master, info)
	if err != nil {
		t.Fatalf("derive %s: %v", info, err)
	}
	return k
}

func sealAll(t *testing.T, subkey, prefix []byte, start uint64, shareID, purpose string, pt []byte) []byte {
	t.Helper()
	out, err := SealStream(subkey, prefix, start, pt, func(index uint64, last bool) []byte {
		return AAD(shareID, purpose, index, last)
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return out
}

func openAll(t *testing.T, subkey, stream []byte, start uint64, shareID, purpose string) []byte {
	t.Helper()
	out, err := OpenStream(subkey, stream, start, func(index uint64, last bool) []byte {
		return AAD(shareID, purpose, index, last)
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return out
}

func randomMaster(t *testing.T) []byte {
	t.Helper()
	m := make([]byte, KeySize)
	if _, err := rand.Read(m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Round trip across the sizes that matter: empty, one byte, exactly one
// frame, one frame plus one byte, several frames, and the 5 MB part boundary
// on either side.
func TestRoundTripSizes(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "file1"))
	prefix, err := NewNoncePrefix()
	if err != nil {
		t.Fatal(err)
	}
	// a resumed stream starts at a nonzero counter, the chunking shape
	sealAll(t, subkey, prefix, 7, "share1", PurposeFile, make([]byte, 10))
	sizes := []int{
		0, 1, 100, FramePlaintextMax - 1, FramePlaintextMax,
		FramePlaintextMax + 1, 3*FramePlaintextMax + 12345,
		5_000_000 - 1, 5_000_000, 5_000_000 + 1,
	}
	for _, n := range sizes {
		pt := make([]byte, n)
		if _, err := rand.Read(pt); err != nil {
			t.Fatal(err)
		}
		ct := sealAll(t, subkey, prefix, 0, "share1", PurposeFile, pt)
		got := openAll(t, subkey, ct, 0, "share1", PurposeFile)
		if !bytes.Equal(pt, got) {
			t.Fatalf("size %d round trip mismatch", n)
		}
	}
}

// A resumed chunk seals from a nonzero counter, that is the resume shape
// the upload path builds on.
func TestNonZeroStartRoundTrip(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	// the head frame is sealed with last=false, only the object tail carries
	// the flag, exactly like the upload pipeline does
	head, err := SealFrame(subkey, prefix, 0, make([]byte, FramePlaintextMax), AAD("s", PurposeFile, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	tail := sealAll(t, subkey, prefix, 1, "s", PurposeFile, []byte("resumed tail"))
	stream := append(head, tail...)
	got := openAll(t, subkey, stream, 0, "s", PurposeFile)
	want := append(make([]byte, FramePlaintextMax), []byte("resumed tail")...)
	if !bytes.Equal(got, want) {
		t.Fatal("nonzero start round trip mismatch")
	}
}

// Every plaintext bit flip in the ciphertext must fail authentication, and
// the failure must be ErrBadFrame so callers never string match.
func TestBitFlipRejected(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	ct := sealAll(t, subkey, prefix, 0, "s", PurposeFile, []byte("attack at dawn"))
	for i := range ct {
		tampered := bytes.Clone(ct)
		tampered[i] ^= 0x01
		_, err := OpenFrame(subkey, tampered, AAD("s", PurposeFile, 0, true))
		if !errors.Is(err, ErrBadFrame) {
			t.Fatalf("flip at byte %d accepted or wrong error: %v", i, err)
		}
	}
}

func TestTruncationRejected(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	pt := make([]byte, 3*FramePlaintextMax+7)
	ct := sealAll(t, subkey, prefix, 0, "s", PurposeFile, pt)
	for _, cut := range []int{1, 12, 13, 14, FramePlaintextMax + FrameOverhead, len(ct) - 1} {
		_, err := OpenStream(subkey, ct[:cut], 0, func(index uint64, last bool) []byte {
			return AAD("s", PurposeFile, index, last)
		})
		if !errors.Is(err, ErrBadFrame) {
			t.Fatalf("truncation to %d accepted: %v", cut, err)
		}
	}
}

func TestReorderRejected(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	pt := make([]byte, 2*FramePlaintextMax)
	ct := sealAll(t, subkey, prefix, 0, "s", PurposeFile, pt)
	stride := FramePlaintextMax + FrameOverhead
	swapped := append(bytes.Clone(ct[stride:2*stride]), ct[:stride]...)
	// last flag now sits on the wrong frame, both frames fail
	if _, err := OpenStream(subkey, swapped, 0, func(index uint64, last bool) []byte {
		return AAD("s", PurposeFile, index, last)
	}); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("reordered frames accepted: %v", err)
	}
}

// A frame from another share, purpose or format version must fail even with
// the right key, that is what the AAD is for.
func TestSpliceRejected(t *testing.T) {
	master := randomMaster(t)
	fileKey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f1"))
	otherFileKey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f2"))
	prefix, _ := NewNoncePrefix()

	frame := sealAll(t, fileKey, prefix, 0, "shareA", PurposeFile, []byte("same key class"))
	for _, wrong := range []struct {
		key     []byte
		shareID string
		purpose string
	}{
		{otherFileKey, "shareA", PurposeFile}, // different subkey
		{fileKey, "shareB", PurposeFile},      // different share id
		{fileKey, "shareA", PurposeManifest},  // different purpose
		{mustSubkey(t, master, SubkeyInfo(PurposeManifest, "")), "shareA", PurposeManifest},
	} {
		if _, err := OpenFrame(wrong.key, frame, AAD(wrong.shareID, wrong.purpose, 0, true)); !errors.Is(err, ErrBadFrame) {
			t.Fatalf("splice accepted: key=%x share=%s purpose=%s", wrong.key[:4], wrong.shareID, wrong.purpose)
		}
	}
}

// The wrong last flag must fail, truncation is not just a short read.
func TestWrongLastFlagRejected(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	frame, err := SealFrame(subkey, prefix, 0, []byte("x"), AAD("s", PurposeFile, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFrame(subkey, frame, AAD("s", PurposeFile, 0, false)); !errors.Is(err, ErrBadFrame) {
		t.Fatal("frame accepted with the wrong last flag")
	}
	// and the index must match too
	if _, err := OpenFrame(subkey, frame, AAD("s", PurposeFile, 1, true)); !errors.Is(err, ErrBadFrame) {
		t.Fatal("frame accepted with the wrong index")
	}
}

// Same prefix, same counter, different subkeys: nonces are unique by
// construction, prove distinct subkeys produce distinct ciphertexts and the
// cross open fails.
func TestNonceUniquenessAcrossSubkeys(t *testing.T) {
	master := randomMaster(t)
	prefix, _ := NewNoncePrefix()
	f1 := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f1"))
	f2 := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f2"))
	c1, _ := SealFrame(f1, prefix, 42, []byte("hello"), AAD("s", PurposeFile, 42, true))
	c2, _ := SealFrame(f2, prefix, 42, []byte("hello"), AAD("s", PurposeFile, 42, true))
	if bytes.Equal(c1, c2) {
		t.Fatal("two subkeys produced identical frames")
	}
	if _, err := OpenFrame(f2, c1, AAD("s", PurposeFile, 42, true)); !errors.Is(err, ErrBadFrame) {
		t.Fatal("frame crossed subkeys")
	}
}

func TestSubkeyInfoSeparation(t *testing.T) {
	master := randomMaster(t)
	infos := []string{
		SubkeyInfo(PurposeFile, "f1"),
		SubkeyInfo(PurposeFile, "f2"),
		SubkeyInfo(PurposeManifest, ""),
		SubkeyInfo(PurposeCheck, ""),
		SubkeyInfo(PurposeTitle, ""),
	}
	seen := make(map[string]bool)
	for _, info := range infos {
		k := mustSubkey(t, master, info)
		if seen[string(k)] {
			t.Fatalf("subkey collision for info %q", info)
		}
		seen[string(k)] = true
	}
}

func TestFrameVersionByteRejected(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeCheck, ""))
	prefix, _ := NewNoncePrefix()
	frame, err := SealFrame(subkey, prefix, 0, []byte("v"), AAD("s", PurposeCheck, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	frame[0] = 0x02
	if _, err := OpenFrame(subkey, frame, AAD("s", PurposeCheck, 0, true)); !errors.Is(err, ErrBadFrame) {
		t.Fatal("future version byte accepted")
	}
}

func TestFragmentKeyDecode(t *testing.T) {
	master := randomMaster(t)
	frag, err := EncodeFragmentKey(master)
	if err != nil {
		t.Fatal(err)
	}
	if len(frag) != FragmentLen {
		t.Fatalf("fragment length %d", len(frag))
	}
	back, err := DecodeFragmentKey(frag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(master, back) {
		t.Fatal("fragment round trip mismatch")
	}

	for _, bad := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too short", strings.Repeat("A", 42)},
		{"too long", strings.Repeat("A", 44)},
		{"standard base64", strings.Replace(frag[:len(frag)-2], "-", "+", 1) + "="},
		{"invalid char", strings.Replace(frag, string(frag[0]), "#", 1)},
		{"non canonical tail", canonicalTail(frag)},
	} {
		if _, err := DecodeFragmentKey(bad.in); err == nil {
			t.Fatalf("%s fragment accepted", bad.name)
		}
	}
}

// canonicalTail sets the two unused trailing bits that forgiving decoders
// silently drop. The flip must set a bit, clearing one could canonicalise
// the value and pass.
func canonicalTail(frag string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := frag[len(frag)-1]
	var val byte
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == last {
			val = byte(i)
			break
		}
	}
	return frag[:len(frag)-1] + string(alphabet[val|1])
}

// The check blob is a fixed 45 bytes: 1 version, 12 nonce, 16 plaintext, 16
// tag. Config pins this number, prove the format agrees.
func TestCheckBlobIs45Bytes(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeCheck, ""))
	prefix, _ := NewNoncePrefix()
	verifier := make([]byte, 16)
	rand.Read(verifier)
	blob, err := SealFrame(subkey, prefix, 0, verifier, AAD("share1", PurposeCheck, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 45 {
		t.Fatalf("check blob is %d bytes, want 45", len(blob))
	}
	opened, err := OpenFrame(subkey, blob, AAD("share1", PurposeCheck, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifier, opened) {
		t.Fatal("check verifier mismatch")
	}
}

// The stride arithmetic the Range to frame mapping depends on.
func TestFrameStrideArithmetic(t *testing.T) {
	master := randomMaster(t)
	subkey := mustSubkey(t, master, SubkeyInfo(PurposeFile, "f"))
	prefix, _ := NewNoncePrefix()
	for _, n := range []int{1, 1000, FramePlaintextMax, FramePlaintextMax + 5, 2 * FramePlaintextMax} {
		ct := sealAll(t, subkey, prefix, 0, "s", PurposeFile, make([]byte, n))
		frames := (n + FramePlaintextMax - 1) / FramePlaintextMax
		want := n + frames*FrameOverhead
		if len(ct) != want {
			t.Fatalf("size %d: ciphertext %d bytes, arithmetic says %d", n, len(ct), want)
		}
	}
}

// Node generates fixtures with WebCrypto, Go must open them byte for byte.
// The generator script is committed next to the fixtures.
func TestOpenNodeGeneratedFixtures(t *testing.T) {
	vectors := loadFixtures(t)
	if len(vectors) < 6 {
		t.Fatalf("want at least 6 fixture vectors, got %d, regenerate with node scripts/gen-fixtures.mjs", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			master, err := DecodeFragmentKey(v.MasterKey)
			if err != nil {
				t.Fatalf("fixture master key: %v", err)
			}
			subkey := mustSubkey(t, master, SubkeyInfo(v.Purpose, v.ID))
			prefix, err := base64.RawURLEncoding.DecodeString(v.NoncePrefix)
			if err != nil || len(prefix) != NoncePrefixSize {
				t.Fatalf("fixture nonce prefix: %v", err)
			}
			ct, err := base64.StdEncoding.DecodeString(v.Ciphertext)
			if err != nil {
				t.Fatalf("fixture ciphertext: %v", err)
			}
			// the prefix in the first frame must match the declared one
			if len(ct) >= HeaderSize && !bytes.Equal(ct[1:1+NoncePrefixSize], prefix) {
				t.Fatal("fixture nonce prefix does not match the first frame")
			}
			got := openAll(t, subkey, ct, 0, v.ShareID, v.Purpose)
			want, err := base64.StdEncoding.DecodeString(v.Plaintext)
			if err != nil {
				t.Fatalf("fixture plaintext: %v", err)
			}
			// an empty vector under a non empty name is a vacuous test
			if len(want) == 0 && !strings.HasSuffix(v.Name, "empty") {
				t.Fatalf("vector %s carries an empty plaintext, regenerate with node scripts/gen-fixtures.mjs", v.Name)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("node fixture %s did not round trip", v.Name)
			}
		})
	}
}

type fixtureVector struct {
	Name        string `json:"name"`
	ShareID     string `json:"share_id"`
	Purpose     string `json:"purpose"`
	ID          string `json:"id"`
	MasterKey   string `json:"master_key"`
	NoncePrefix string `json:"nonce_prefix"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
}

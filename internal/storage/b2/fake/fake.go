// Package fake is an in-memory b2.Store for tests and local development
// without a bucket. It is never wired in production, the constructor for the
// real client lives in the minio subpackage.
package fake

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/dreamfast/dreamshare/internal/storage/b2"
)

// Store keeps objects and multipart uploads in memory.
type Store struct {
	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]*upload
	nextErr map[string]error
}

type upload struct {
	key   string
	parts map[int]b2.PartInfo
	data  map[int][]byte
}

// New returns an empty store.
func New() *Store {
	return &Store{
		objects: map[string][]byte{},
		uploads: map[string]*upload{},
		nextErr: map[string]error{},
	}
}

// FailNext makes the next call with the exact method name fail once, for
// retry path tests.
func (s *Store) FailNext(method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextErr[method] = err
}

func (s *Store) check(method string) error {
	if err, ok := s.nextErr[method]; ok {
		delete(s.nextErr, method)
		return err
	}
	return nil
}

func (s *Store) Head(_ context.Context) error { return s.check("Head") }

func (s *Store) PutObject(_ context.Context, key string, size int64, body io.Reader) (b2.Completed, error) {
	if err := s.check("PutObject"); err != nil {
		return b2.Completed{}, err
	}
	data, err := io.ReadAll(io.LimitReader(body, size))
	if err != nil {
		return b2.Completed{}, err
	}
	if int64(len(data)) != size {
		return b2.Completed{}, fmt.Errorf("short read, %d of %d", len(data), size)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = data
	return b2.Completed{ETag: fmt.Sprintf("etag-%s", key), VersionID: "v-" + key}, nil
}

func (s *Store) CreateUpload(_ context.Context, key string) (string, error) {
	if err := s.check("CreateUpload"); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := fmt.Sprintf("up-%d", len(s.uploads)+1)
	s.uploads[id] = &upload{key: key, parts: map[int]b2.PartInfo{}, data: map[int][]byte{}}
	return id, nil
}

func (s *Store) PutPart(_ context.Context, _, uploadID string, partNumber int, size int64, body io.Reader) (b2.PartInfo, error) {
	if err := s.check("PutPart"); err != nil {
		return b2.PartInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(body, size))
	if err != nil {
		return b2.PartInfo{}, err
	}
	if int64(len(data)) != size {
		return b2.PartInfo{}, fmt.Errorf("short read, %d of %d", len(data), size)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uploads[uploadID]
	if !ok {
		return b2.PartInfo{}, b2.ErrNotFound
	}
	u.parts[partNumber] = b2.PartInfo{Number: partNumber, ETag: fmt.Sprintf("etag-%s-%d", uploadID, partNumber), Size: size}
	u.data[partNumber] = data
	return u.parts[partNumber], nil
}

func (s *Store) CompleteUpload(_ context.Context, _, uploadID string, parts []b2.PartInfo) (b2.Completed, error) {
	if err := s.check("CompleteUpload"); err != nil {
		return b2.Completed{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uploads[uploadID]
	if !ok {
		return b2.Completed{}, b2.ErrNotFound
	}
	// model the real invalid part refusal: every presented etag must
	// belong to this upload. the api once minted two mpus for one file
	// under a first part race and the parts scattered across them, a fake
	// that blessed any etag hid the bug
	for _, p := range parts {
		stored, ok := u.parts[p.Number]
		if !ok || stored.ETag != p.ETag {
			return b2.Completed{}, fmt.Errorf(
				"invalid part %d: not uploaded to this upload or etag mismatch", p.Number)
		}
	}
	var buf bytes.Buffer
	var nums []int
	for n := range u.parts {
		nums = append(nums, n)
	}
	slices.Sort(nums)
	for _, n := range nums {
		buf.Write(u.data[n])
	}
	s.objects[u.key] = buf.Bytes()
	delete(s.uploads, uploadID)
	return b2.Completed{ETag: "etag-" + u.key, VersionID: "v-" + u.key}, nil
}

func (s *Store) AbortUpload(_ context.Context, _, uploadID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.uploads[uploadID]; !ok {
		return b2.ErrNotFound
	}
	delete(s.uploads, uploadID)
	return nil
}

func (s *Store) ListParts(_ context.Context, _, uploadID string) ([]b2.PartInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.uploads[uploadID]
	if !ok {
		return nil, b2.ErrNotFound
	}
	var out []b2.PartInfo
	for _, p := range u.parts {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b b2.PartInfo) int { return a.Number - b.Number })
	return out, nil
}

func (s *Store) Get(_ context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	if !ok {
		return nil, b2.ErrNotFound
	}
	if offset < 0 || offset > int64(len(data)) {
		return nil, fmt.Errorf("offset %d out of range for %d bytes", offset, len(data))
	}
	end := int64(len(data))
	if length >= 0 && offset+length < end {
		end = offset + length
	}
	return io.NopCloser(bytes.NewReader(data[offset:end])), nil
}

func (s *Store) Size(_ context.Context, key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.objects[key]
	if !ok {
		return 0, b2.ErrNotFound
	}
	return int64(len(data)), nil
}

func (s *Store) DeleteVersion(_ context.Context, key, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[key]; !ok {
		return b2.ErrNotFound
	}
	delete(s.objects, key)
	return nil
}

// Keys lists stored object keys, for orphan sweep tests.
func (s *Store) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.objects))
	for k := range s.objects {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

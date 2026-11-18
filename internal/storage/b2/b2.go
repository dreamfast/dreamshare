// Package b2 is the object storage seam. The minio client backs it in
// production, tests run on the in-memory double in the fake subpackage.
package b2

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound means the object or upload id is unknown to the store.
var ErrNotFound = errors.New("object not found")

// PartInfo is one uploaded part of a multipart upload.
type PartInfo struct {
	Number int
	ETag   string
	Size   int64
}

// Completed describes a stored object.
type Completed struct {
	ETag      string
	VersionID string // the b2 file id when the store surfaces one
}

// Store is everything the handlers need from object storage. Chunked uploads
// stream through PutPart, downloads stream through Get.
type Store interface {
	// Head verifies reachability at startup and by the health endpoints.
	Head(ctx context.Context) error

	// PutObject stores a whole small object, the one chunk or less path.
	PutObject(ctx context.Context, key string, size int64, body io.Reader) (Completed, error)

	// CreateUpload starts a multipart upload for objects above one chunk.
	CreateUpload(ctx context.Context, key string) (uploadID string, err error)

	// PutPart stores one part with a known size. The S3 multipart calls all
	// take the object key alongside the upload id, so the seam passes both.
	// B2 refuses chunked transfer encoding, the size must be declared.
	PutPart(ctx context.Context, key, uploadID string, partNumber int, size int64, body io.Reader) (PartInfo, error)

	// CompleteUpload finishes a multipart upload from its part list.
	CompleteUpload(ctx context.Context, key, uploadID string, parts []PartInfo) (Completed, error)

	// AbortUpload cancels an unfinished multipart upload so abandoned parts
	// stop billing.
	AbortUpload(ctx context.Context, key, uploadID string) error

	// ListParts reports which parts of an upload already landed, the resume
	// path cross checks the local table against this.
	ListParts(ctx context.Context, key, uploadID string) ([]PartInfo, error)

	// Get streams the object. When length is negative the whole object is
	// read, otherwise the inclusive byte range. Callers must Close the body.
	Get(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)

	// Size returns the object byte size, used to sanity check the ledger.
	Size(ctx context.Context, key string) (int64, error)

	// DeleteVersion removes one specific file version. The object key rides
	// along because the native b2 delete validates the fileId and fileName
	// pair, an s3 style delete leaves a hidden version behind and the bytes
	// keep billing.
	DeleteVersion(ctx context.Context, key, fileID string) error
}

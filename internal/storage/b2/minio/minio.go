// Package minio implements the b2.Store interface against the S3 compatible
// endpoint of a Backblaze B2 bucket. The native API client in the native
// package covers the calls S3 cannot express, deleting a specific file
// version above all.
package minio

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dreamfast/dreamshare/internal/storage/b2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config is the S3 data path configuration.
type Config struct {
	Endpoint string // host only, s3.us-west-002.backblazeb2.com
	Region   string
	Bucket   string
	KeyID    string
	AppKey   string
	// Secure defaults to true, only a local dev endpoint turns it off
	Secure *bool
	// Deleter routes version deletes to the native api, the S3 endpoint
	// cannot express them. Without it DeleteVersion fails loudly.
	Deleter VersionDeleter
}

// VersionDeleter is the native delete the S3 data path cannot express.
type VersionDeleter interface {
	DeleteVersion(ctx context.Context, key, fileID string) error
}

// Client wraps the minio SDK. Version capture is the design sensitive part:
// every put path records the version id when the endpoint returns one.
type Client struct {
	mc   *minio.Client
	core minio.Core
	cfg  Config
}

// New builds the client and pings the bucket.
func New(ctx context.Context, cfg Config) (*Client, error) {
	secure := true
	if cfg.Secure != nil {
		secure = *cfg.Secure
	}
	mc, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.KeyID, cfg.AppKey, ""),
		Secure: secure,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, err
	}
	c := &Client{mc: mc, core: minio.Core{Client: mc}, cfg: cfg}
	if err := c.Head(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) Head(ctx context.Context) error {
	exists, err := c.mc.BucketExists(ctx, c.cfg.Bucket)
	if err != nil {
		return fmt.Errorf("bucket head: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", c.cfg.Bucket)
	}
	return nil
}

func (c *Client) PutObject(ctx context.Context, key string, size int64, body io.Reader) (b2.Completed, error) {
	info, err := c.mc.PutObject(ctx, c.cfg.Bucket, key, body, size,
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return b2.Completed{}, fmt.Errorf("put %s: %w", key, err)
	}
	return b2.Completed{ETag: strings.Trim(info.ETag, `"`), VersionID: info.VersionID}, nil
}

func (c *Client) CreateUpload(ctx context.Context, key string) (string, error) {
	id, err := c.core.NewMultipartUpload(ctx, c.cfg.Bucket, key, minio.PutObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("create mpu %s: %w", key, err)
	}
	return id, nil
}

func (c *Client) PutPart(ctx context.Context, key, uploadID string, partNumber int, size int64, body io.Reader) (b2.PartInfo, error) {
	info, err := c.core.PutObjectPart(ctx, c.cfg.Bucket, key, uploadID, partNumber, body, size,
		minio.PutObjectPartOptions{})
	if err != nil {
		return b2.PartInfo{}, fmt.Errorf("part %d: %w", partNumber, err)
	}
	return b2.PartInfo{Number: partNumber, ETag: strings.Trim(info.ETag, `"`), Size: info.Size}, nil
}

func (c *Client) CompleteUpload(ctx context.Context, key, uploadID string, parts []b2.PartInfo) (b2.Completed, error) {
	var objs []minio.CompletePart
	for _, p := range parts {
		objs = append(objs, minio.CompletePart{PartNumber: p.Number, ETag: p.ETag})
	}
	info, err := c.core.CompleteMultipartUpload(ctx, c.cfg.Bucket, key, uploadID, objs, minio.PutObjectOptions{})
	if err != nil {
		return b2.Completed{}, fmt.Errorf("complete mpu %s: %w", key, err)
	}
	return b2.Completed{ETag: strings.Trim(info.ETag, `"`), VersionID: info.VersionID}, nil
}

func (c *Client) AbortUpload(ctx context.Context, key, uploadID string) error {
	if err := c.core.AbortMultipartUpload(ctx, c.cfg.Bucket, key, uploadID); err != nil {
		if resp := minio.ToErrorResponse(err); resp.Code == "NoSuchUpload" {
			return b2.ErrNotFound
		}
		return fmt.Errorf("abort mpu %s: %w", key, err)
	}
	return nil
}

func (c *Client) ListParts(ctx context.Context, key, uploadID string) ([]b2.PartInfo, error) {
	res, err := c.core.ListObjectParts(ctx, c.cfg.Bucket, key, uploadID, 0, 10000)
	if err != nil {
		if resp := minio.ToErrorResponse(err); resp.Code == "NoSuchUpload" {
			return nil, b2.ErrNotFound
		}
		return nil, fmt.Errorf("list parts: %w", err)
	}
	var out []b2.PartInfo
	for _, o := range res.ObjectParts {
		out = append(out, b2.PartInfo{Number: o.PartNumber, ETag: strings.Trim(o.ETag, `"`), Size: o.Size})
	}
	return out, nil
}

func (c *Client) Get(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 || length == 0 {
		// a zero length range is undefined in the seam and bytes=-1 would
		// silently serve the last byte on some sdk paths
		return nil, fmt.Errorf("invalid range offset %d length %d", offset, length)
	}
	opts := minio.GetObjectOptions{}
	if length >= 0 {
		// an explicit range, inclusive end. a negative length means the
		// whole object from offset, which is no Range header at all when
		// offset is zero, SetRange(0,0) would fetch exactly one byte
		if err := opts.SetRange(offset, offset+length-1); err != nil {
			return nil, err
		}
	} else if offset > 0 {
		if err := opts.SetRange(offset, 0); err != nil {
			return nil, err
		}
	}
	obj, err := c.mc.GetObject(ctx, c.cfg.Bucket, key, opts)
	if err != nil {
		if resp := minio.ToErrorResponse(err); resp.StatusCode == http.StatusNotFound {
			return nil, b2.ErrNotFound
		}
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	// stat forces the first byte, a 404 surfaces here rather than mid copy
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		if resp := minio.ToErrorResponse(err); resp.StatusCode == http.StatusNotFound {
			return nil, b2.ErrNotFound
		}
		return nil, fmt.Errorf("stat %s: %w", key, err)
	}
	return obj, nil
}

func (c *Client) Size(ctx context.Context, key string) (int64, error) {
	info, err := c.mc.StatObject(ctx, c.cfg.Bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if resp := minio.ToErrorResponse(err); resp.StatusCode == http.StatusNotFound {
			return 0, b2.ErrNotFound
		}
		return 0, err
	}
	return info.Size, nil
}

// DeleteVersion routes to the native client, the S3 endpoint cannot express
// a delete of one specific version.
func (c *Client) DeleteVersion(ctx context.Context, key, fileID string) error {
	if c.cfg.Deleter == nil {
		return fmt.Errorf("delete by version needs the native api, none wired")
	}
	return c.cfg.Deleter.DeleteVersion(ctx, key, fileID)
}

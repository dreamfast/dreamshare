// Package webdist embeds the built SPA. The dist directory is copied here
// by the Makefile before the go build, so the binary ships one artefact
// with no host bind mounts.
package webdist

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the built SPA rooted at dist.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// the embed directive guarantees the tree, this cannot fail
		panic(err)
	}
	return sub
}

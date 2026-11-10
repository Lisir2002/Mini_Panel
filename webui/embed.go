// Package webui embeds the compiled front end into the panel binary, so a single
// file is the whole deliverable: no nginx vhost for the UI, no static root to
// install, no path that has to exist at runtime.
//
// web/dist is produced by `make web` (Vite, outDir = ../webui/dist). The embed
// directive uses "all:" so that dotfiles inside the build output are included
// rather than silently dropped.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Assets is rooted at the package directory; consumers take fs.Sub(Assets, "dist").
var Assets fs.FS = embedded

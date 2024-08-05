package frpc

import (
	"embed"

	"github.com/xx/xxx/assets"
)

//go:embed static/*
var content embed.FS

func init() {
	assets.Register(content)
}

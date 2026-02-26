// Package web provides embedded static assets for the ShellGate web terminal.
package web

import "embed"

//go:embed static/*
var Assets embed.FS

package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedAssets(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"index.html", "static/index.html"},
		{"terminal.js", "static/terminal.js"},
		{"style.css", "static/style.css"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Assets.ReadFile(tt.path)
			require.NoError(t, err)
			assert.NotEmpty(t, data, "embedded file %s should not be empty", tt.path)
		})
	}
}

func TestEmbeddedAssetsNotFound(t *testing.T) {
	_, err := Assets.ReadFile("static/nonexistent.txt")
	assert.Error(t, err)
}

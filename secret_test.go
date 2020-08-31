package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretRedact(t *testing.T) {
	samples := []struct {
		secret *Secret
		data   [][]string // {original, redacted}
	}{
		{
			secret: NewSecret("secret", BlackOut, []byte("#")),
			data: [][]string{
				{"Here is a secret", "Here is a ######"},
				{"There is a secret within this text", "There is a ###### within this text"},
			},
		},
		{
			secret: NewSecret("secret", Censor, []byte("<REDACTED>")),
			data: [][]string{
				{"Here is a secret", "Here is a <REDACTED>"},
				{"There is a secret within this text", "There is a <REDACTED> within this text"},
			},
		},
		{
			secret: NewSecret("[0-9]", ReplaceData, []byte("<REDACTED>")),
			data: [][]string{
				{"123", "<REDACTED>"},
				{"a1b2c3", "<REDACTED>"},
			},
		},
	}

	for _, s := range samples {
		for _, d := range s.data {
			assert.Equal(t, []byte(d[1]), s.secret.Redact([]byte(d[0])))
		}
	}
}

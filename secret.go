package redact

import (
	"bytes"
	"regexp"
	"unicode/utf8"
)

// Protection defines a strategy to protect a secret
type Protection int

const (
	// BlackOut protects by replacing each charecter of the secret with another symbol
	BlackOut Protection = iota
	// Censor protects by censoring the whole secret with a replacement
	Censor
	// OmitData protects by replacing the whole data
	OmitData
)

// Secret defines what parts of a string most be redacted and how
type Secret struct {
	Pattern     *regexp.Regexp
	Protection  Protection
	Replacement []byte
}

// NewSecret creates a new secret
func NewSecret(pattern string, p Protection, r []byte) *Secret {
	re, _ := regexp.Compile(pattern)
	return &Secret{
		Pattern:     re,
		Protection:  p,
		Replacement: r,
	}
}

// Redact redacts the secrets from data
func (s *Secret) Redact(data []byte) []byte {
	if s.Pattern.Match(data) {
		switch s.Protection {
		case BlackOut:
			return s.Pattern.ReplaceAllFunc(
				data,
				func(b []byte) []byte {
					redacted := bytes.Repeat(
						s.Replacement,
						utf8.RuneCountInString(string(b)),
					)
					return []byte(redacted)
				},
			)
		case Censor:
			return s.Pattern.ReplaceAll(data, s.Replacement)
		case OmitData:
			return s.Replacement
		}
	}
	return data
}

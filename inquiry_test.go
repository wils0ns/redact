package redacting

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInquiryRedact(t *testing.T) {

	samples := []struct {
		original, expected string
	}{
		{"secret Wilson", "###### #REDACTED#"},
		{
			"This is the secret in the text and it belongs to Wilson",
			"This is the ###### in the text and it belongs to #REDACTED#",
		},
		{
			"This text makes no sense without the secret and should be omitted",
			"",
		},
		{
			`{
	"name": "Wilson",
	"address": "123 Purple House ln",
	"quote": "There is a secret about Wilson in this quote",
	"phrases": [
		"This phrase is ok",
		"There is a secret in this phrase"
	],
	"articles": [
		{
			"title": "Article 01",
			"date": "2020-08-30 10:45:59+00:00",
			"content": "This article has a secret"
		}
	]
}`,
			`{
	"name": "#REDACTED#",
	"quote": "There is a ###### about #REDACTED# in this quote",
	"phrases": [
		"This phrase is ok",
		"There is a ###### in this phrase"
	],
	"articles": [
		{
			"title": "Article 01",
			"content": "This article has a ######"
		}
	]
}`,
		},
	}

	inq := &Inquiry{}
	inq.AddSecretValue(NewSecret("secret", BlackOut, []byte("#")))
	inq.AddSecretValue(NewSecret("Wilson", Censor, []byte("#REDACTED#")))
	inq.AddSecretValue(NewSecret("omitted", OmitData, []byte("")))
	inq.SecretFields = []string{"address", "date"}

	for _, s := range samples {
		actual, err := inq.Redact([]byte(s.original))
		if err != nil {
			t.Error(err)
		}

		var expectedData interface{}
		err = json.Unmarshal([]byte(s.expected), &expectedData)
		if err != nil {
			assert.Equal(t, s.expected, string(actual))
		} else {
			expected, _ := json.Marshal(expectedData)
			assert.Equal(t, expected, actual)
		}
	}
}

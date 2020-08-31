package redact

import (
	"fmt"
)

func ExampleSecret_Redact() {

	// Censor example: simple word
	data := []byte("There is a secret word here")
	s := NewSecret("secret", Censor, []byte("#REDACTED#"))
	fmt.Println(string(s.Redact(data)))

	// BlackOut example: regular expression
	data = []byte("These are a couple of CPFs: 321.654.987-00 and 789.456.123-00")
	s = NewSecret(`[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}`, BlackOut, []byte("█"))
	fmt.Println(string(s.Redact(data)))

	// OmitData example
	data = []byte("Something about the government")
	s = NewSecret("government", OmitData, []byte("Text about flowers"))
	fmt.Println(string(s.Redact(data)))

	// Output:
	// There is a #REDACTED# word here
	// These are a couple of CPFs: ██████████████ and ██████████████
	// Text about flowers
}

func ExampleInquiry_Redact() {

	bo := []byte("█")
	inq := New()
	inq.AddSecretValue(NewSecret("secret[s]?", BlackOut, bo))
	inq.AddSecretValue(NewSecret("SSN", BlackOut, []byte("")))
	inq.AddSecretValue(NewSecret(
		`[1-9]{3}-[1-9]{2}-[1-9]{4}`, BlackOut, bo))

	inq.AddSecretField("date")
	inq.AddSecretField("^SSN$")

	// Redact text example
	data := []byte(`This text has more than one type of secret. Here is someone's SSN 987-65-4321`)
	r, err := inq.Redact(data)
	if err != nil {
		// Handle error
	}
	fmt.Println(string(r))

	// Redact JSON example
	data = []byte(`{
		"Name":"Wilson",
		"create_date": "2020-08-31 15:51:14+00:00",
		"modify_date": "2020-08-31 15:52:15+00:00",
		"SSN": "123-45-6789",
		"quote": "We all have secrets"}`)
	r, err = inq.Redact(data)
	if err != nil {
		// Handle error
	}
	fmt.Println(string(r))

	// Output:
	// This text has more than one type of ██████. Here is someone's  ███████████
	// {"Name":"Wilson","quote":"We all have ███████"}
}

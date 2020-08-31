package redact

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
)

// Inquiry provide ways to request data considering what needs to remain secret
type Inquiry struct {
	SecretValues        []*Secret
	secretFieldPatterns []*regexp.Regexp
}

// New creates an empty inquiry
func New() *Inquiry {
	return &Inquiry{}
}

// AddSecretValue adds a Secret definition to redact data values
func (inq *Inquiry) AddSecretValue(s *Secret) {
	inq.SecretValues = append(inq.SecretValues, s)
}

// RedactValue redacts a value based on all Inquiry.SecretValues
func (inq *Inquiry) redactValue(data []byte) []byte {
	redacted := data
	for _, s := range inq.SecretValues {
		if bytes.Compare(redacted, []byte("")) == 0 {
			return redacted
		}
		redacted = s.Redact(redacted)
	}
	return redacted
}

// AddSecretField adds a secret field regexp patterns to redact maps by key.
// Map keys are redacted by deleting the key-value pair entirely
func (inq *Inquiry) AddSecretField(f string) error {
	re, err := regexp.Compile(f)
	if err != nil {
		return err
	}
	inq.secretFieldPatterns = append(inq.secretFieldPatterns, re)
	return nil
}

// isSecretField checks if string matches on of the secret fields
func (inq *Inquiry) isSecretField(f string) bool {
	for _, sf := range inq.secretFieldPatterns {
		if sf.Match([]byte(f)) {
			return true
		}
	}
	return false
}

// redact visits all fields of an object checking for secrets
func (inq *Inquiry) redact(copy, original reflect.Value) {
	switch original.Kind() {
	case reflect.Ptr:
		originalValue := original.Elem()
		if !originalValue.IsValid() {
			return
		}
		copy.Set(reflect.New(originalValue.Type()))
		inq.redact(copy.Elem(), originalValue)

	case reflect.Interface:
		originalValue := original.Elem()
		copyValue := reflect.New(originalValue.Type()).Elem()
		inq.redact(copyValue, originalValue)
		copy.Set(copyValue)

	case reflect.Struct:
		for i := 0; i < original.NumField(); i++ {
			inq.redact(copy.Field(i), original.Field(i))
		}

	case reflect.Slice:
		copy.Set(reflect.MakeSlice(original.Type(), original.Len(), original.Cap()))
		for i := 0; i < original.Len(); i++ {
			inq.redact(copy.Index(i), original.Index(i))
		}

	case reflect.Map:
		copy.Set(reflect.MakeMap(original.Type()))
		for _, key := range original.MapKeys() {
			if inq.isSecretField(key.Interface().(string)) {
				continue
			}
			originalValue := original.MapIndex(key)
			copyValue := reflect.New(originalValue.Type()).Elem()
			inq.redact(copyValue, originalValue)
			copy.SetMapIndex(key, copyValue)
		}

	case reflect.String:
		redacted := inq.redactValue([]byte(original.Interface().(string)))
		copy.SetString(string(redacted))

	default:
		copy.Set(original)
	}

}

// Redact redacts the inquired data
func (inq *Inquiry) Redact(data []byte) ([]byte, error) {
	var structData interface{}
	err := json.Unmarshal(data, &structData)
	if err != nil {
		return inq.redactValue(data), nil
	}
	original := reflect.ValueOf(structData)
	copy := reflect.New(original.Type()).Elem()
	inq.redact(copy, original)
	return json.Marshal(copy.Interface())
}

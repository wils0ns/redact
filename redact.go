package redacting

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// Inquiry provide ways to request data considering what needs to remain secret
type Inquiry struct {
	SecretValues []*Secret
	SecretKeys   []string
}

// TODO AddSecretValue
// TODO AddSecretKey

// AddSecretValue adds a Secret definition to redact inquiry values
func (inq *Inquiry) AddSecretValue(s *Secret) {
	inq.SecretValues = append(inq.SecretValues, s)
}

// RedactValue redacts a value based on all Inquiry.SecretValues
func (inq *Inquiry) RedactValue(data []byte) []byte {
	redacted := data
	for _, s := range inq.SecretValues {
		if bytes.Compare(redacted, []byte("")) == 0 {
			return redacted
		}
		redacted = s.Redact(redacted)
	}
	return redacted
}

func (inq *Inquiry) isSecretKey(k string) bool {
	for _, sk := range inq.SecretKeys {
		if k == sk {
			return true
		}
	}
	return false
}

func (inq *Inquiry) walk(copy, original reflect.Value) {
	switch original.Kind() {
	case reflect.Ptr:
		originalValue := original.Elem()
		if !originalValue.IsValid() {
			return
		}
		copy.Set(reflect.New(originalValue.Type()))
		inq.walk(copy.Elem(), originalValue)

	case reflect.Interface:
		originalValue := original.Elem()
		copyValue := reflect.New(originalValue.Type()).Elem()
		inq.walk(copyValue, originalValue)
		copy.Set(copyValue)

	case reflect.Struct:
		for i := 0; i < original.NumField(); i++ {
			inq.walk(copy.Field(i), original.Field(i))
		}

	case reflect.Slice:
		copy.Set(reflect.MakeSlice(original.Type(), original.Len(), original.Cap()))
		for i := 0; i < original.Len(); i++ {
			inq.walk(copy.Index(i), original.Index(i))
		}

	case reflect.Map:
		copy.Set(reflect.MakeMap(original.Type()))
		for _, key := range original.MapKeys() {
			if inq.isSecretKey(key.Interface().(string)) {
				continue
			}
			originalValue := original.MapIndex(key)
			copyValue := reflect.New(originalValue.Type()).Elem()
			inq.walk(copyValue, originalValue)
			copy.SetMapIndex(key, copyValue)
		}

	case reflect.String:
		redacted := inq.RedactValue([]byte(original.Interface().(string)))
		copy.SetString(string(redacted))

	default:
		copy.Set(original)
	}

}

// RedactData redacts the inquired data
func (inq *Inquiry) RedactData(data []byte) ([]byte, error) {
	var structData interface{}
	err := json.Unmarshal(data, &structData)
	if err != nil {
		return inq.RedactValue(data), nil
	}
	original := reflect.ValueOf(structData)
	copy := reflect.New(original.Type()).Elem()
	inq.walk(copy, original)
	return json.Marshal(copy.Interface())
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Reject duplicate names before decoding, including within opaque signed JSON.
// Struct fields are matched case-sensitively. Projections may retain unknown
// OCI/SLSA extension fields but never a case variant of a field we consume.
func strictDecode(raw []byte, value any, projection bool) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 128 {
			return errors.New("JSON depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return errors.New("duplicate JSON member")
					}
					seen[name] = true
					if err := scan(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := scan(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("unexpected JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if err := checkJSONFields(raw, reflect.TypeOf(value), projection); err != nil {
		return err
	}
	return json.Unmarshal(raw, value)
}

func checkJSONFields(raw []byte, kind reflect.Type, projection bool) error {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == reflect.TypeOf(json.RawMessage{}) || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	switch kind.Kind() {
	case reflect.Struct:
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			return err
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for name, member := range members {
			field, ok := fields[name]
			if !ok {
				for expected := range fields {
					if strings.EqualFold(name, expected) {
						return errors.New("case-variant JSON member")
					}
				}
				if !projection {
					return errors.New("unknown JSON member")
				}
				continue
			}
			if err := checkJSONFields(member, field, projection); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := checkJSONFields(item, kind.Elem(), projection); err != nil {
				return err
			}
		}
	case reflect.Map:
		var items map[string]json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := checkJSONFields(item, kind.Elem(), projection); err != nil {
				return err
			}
		}
	}
	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"io"
)

// Duplicate keys can make two consumers interpret the same signed bytes differently.
func uniqueJSONFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	budget := 1 << 20
	if !consumeUniqueJSON(decoder, 0, &budget) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeUniqueJSON(decoder *json.Decoder, depth int, budget *int) bool {
	*budget--
	if depth > 64 || *budget < 0 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err = decoder.Token()
			if err != nil {
				return false
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return false
			}
			seen[key] = true
			if !consumeUniqueJSON(decoder, depth+1, budget) {
				return false
			}
		}
		token, err = decoder.Token()
		return err == nil && token == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueJSON(decoder, depth+1, budget) {
				return false
			}
		}
		token, err = decoder.Token()
		return err == nil && token == json.Delim(']')
	default:
		return false
	}
}

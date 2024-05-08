package m3u8

import (
	"io"
	"slices"
)

// https://datatracker.ietf.org/doc/html/draft-pantos-hls-rfc8216bis-14#section-4.4.4.4
type Keys []Key

func NewKeys(keys ...Key) *Keys {
	return (*Keys)(&keys)
}

func (keys *Keys) Len() int {
	if keys == nil {
		return 0
	}
	return len(*keys)
}

// returns copy of keys if update is needed
func (keys *Keys) AddOrUpdateKey(newKey Key) *Keys {
	if newKey.Method == "NONE" {
		return nil
	}

	if keys == nil || len(*keys) == 0 {
		return &Keys{newKey}
	}

	idx := slices.IndexFunc(*keys, func(key Key) bool {
		return key.Keyformat == newKey.Keyformat
	})

	newKeys := make(Keys, len(*keys), len(*keys)+1)
	copy(newKeys, *keys)
	if idx < 0 {
		newKeys = append(newKeys, newKey)
	} else {
		newKeys[idx] = newKey
	}
	return &newKeys
}

func (keys *Keys) Diff(otherKeys *Keys) *Keys {
	if keys == nil || otherKeys == nil {
		return keys
	}
	var res Keys
	for _, key := range *keys {
		if !slices.Contains(*otherKeys, key) {
			res = append(res, key)
		}
	}
	return &res
}

func (keys *Keys) WriteTo(w io.Writer) (n int64, err error) {
	if keys == nil {
		return 0, nil
	}

	for _, key := range *keys {
		count, err := key.WriteTo(w)
		n += count
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Key structure represents information about stream encryption.
//
// Realizes EXT-X-KEY tag.
type Key struct {
	Method            string
	URI               string
	IV                string
	Keyformat         string
	Keyformatversions string
}

func (k Key) WriteTo(w io.Writer) (n int64, err error) {
	n += writeString(w, "#EXT-X-KEY:", &err)
	n += writeString(w, "METHOD=", &err)
	n += writeString(w, k.Method, &err)
	if k.Method != "NONE" {
		n += writeString(w, ",URI=\"", &err)
		n += writeString(w, k.URI, &err)
		n += writeString(w, `"`, &err)
		if len(k.IV) > 0 {
			n += writeString(w, ",IV=", &err)
			n += writeString(w, k.IV, &err)
		}
		if len(k.Keyformat) > 0 {
			n += writeString(w, ",KEYFORMAT=\"", &err)
			writeString(w, k.Keyformat, &err)
			writeString(w, `"`, &err)
		}
		if len(k.Keyformatversions) > 0 {
			writeString(w, ",KEYFORMATVERSIONS=\"", &err)
			writeString(w, k.Keyformatversions, &err)
			writeString(w, `"`, &err)
		}
	}
	writeString(w, "\n", &err)
	return n, err
}

func writeString(w io.Writer, s string, err *error) int64 {
	if *err != nil {
		return 0
	}
	var n int
	n, *err = io.WriteString(w, s)
	return int64(n)
}

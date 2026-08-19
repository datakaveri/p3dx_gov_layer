package db

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// base36 alphabet used by JS Number.toString(36).
const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"

// randBase36 returns n random base36 characters, reproducing the
// Math.random().toString(36).substr(...) suffixes used for ids in the Node code.
func randBase36(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = base36[rand.Intn(len(base36))]
	}
	return string(b)
}

// newID builds an id like the Node ones: "<prefix>-<unixMillis>-<randN>".
func newID(prefix string, randLen int) string {
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixMilli(), randBase36(randLen))
}

// jsonbOr returns raw JSON bytes for a jsonb parameter, falling back to def when
// the value is absent or JSON null (mirrors `value || {}` / `value || []`).
func jsonbOr(raw json.RawMessage, def string) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte(def)
	}
	return []byte(raw)
}

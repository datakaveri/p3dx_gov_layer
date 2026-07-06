package db

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
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

// FlexFloat accepts a JSON number OR a numeric string (the loosely-typed values
// the UI sends from <input type="number">, which may be either), as well as
// null/absent. An empty or non-numeric string is treated as unset, matching the
// JS `value || null` falsy handling (and avoiding a hard error on bad input).
type FlexFloat struct {
	set bool
	val float64
}

func (f *FlexFloat) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	if b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		str = strings.TrimSpace(str)
		if str == "" {
			return nil
		}
		v, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return nil // non-numeric string -> unset (null), do not fail the request
		}
		f.set, f.val = true, v
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	f.set, f.val = true, v
	return nil
}

// NewFlexFloat builds a set FlexFloat from a numeric value (used by the gRPC
// path, where proto numerics arrive as concrete int32/float64). A zero value is
// still subject to the `value || null` coercion (0 => SQL NULL).
func NewFlexFloat(v float64) FlexFloat { return FlexFloat{set: true, val: v} }

// ptr returns a *float64 (nil when unset) for the truthy* coercions.
func (f FlexFloat) ptr() *float64 {
	if f.set {
		v := f.val
		return &v
	}
	return nil
}

// --- "falsy => null" coercions, matching JS `value || null` semantics where 0
// and "" are falsy and therefore stored as SQL NULL. ---

func truthyInt(p *float64) any {
	if p != nil && *p != 0 {
		return int32(*p)
	}
	return nil
}

func truthyBigInt(p *float64) any {
	if p != nil && *p != 0 {
		return int64(*p)
	}
	return nil
}

func truthyFloat(p *float64) any {
	if p != nil && *p != 0 {
		return *p
	}
	return nil
}

func truthyStr(p *string) any {
	if p != nil && *p != "" {
		return *p
	}
	return nil
}

// jsonbOr returns raw JSON bytes for a jsonb parameter, falling back to def when
// the value is absent or JSON null (mirrors `value || {}` / `value || []`).
func jsonbOr(raw json.RawMessage, def string) []byte {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte(def)
	}
	return []byte(raw)
}

package db

import "strconv"

// Real mirrors node-postgres' handling of a REAL (float4) column. pgx's binary
// decode widens the stored float32 to float64 (so 0.01 becomes
// 0.009999999776...), whereas node-postgres parses Postgres' shortest-decimal
// text ("0.01"). Emitting the shortest round-trippable float32 decimal keeps the
// JSON output identical to the Node service.
type Real float32

func (r Real) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(float64(r), 'g', -1, 32)), nil
}

// F64 returns the value as a float64 (for proto mapping etc.).
func (r *Real) F64() float64 {
	if r == nil {
		return 0
	}
	return float64(*r)
}

// BigInt mirrors node-postgres' default of returning a BIGINT (int8) column as a
// JSON string (it does this to avoid precision loss for values beyond 2^53).
type BigInt int64

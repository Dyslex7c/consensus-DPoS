package utils

import (
	"encoding/binary"
)

// PutUint64 writes a uint64 value to a byte slice in big-endian order.
// The byte slice must have at least 8 bytes available.
func PutUint64(b []byte, v uint64) {
	binary.BigEndian.PutUint64(b, v)
}

// Uint64FromBytes reads a uint64 value from a byte slice in big-endian order.
// The byte slice must have at least 8 bytes.
func Uint64FromBytes(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

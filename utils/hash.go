package utils

import (
	"crypto/sha256"
)

// Hash calculates the SHA-256 hash of the input data
// Returns the resulting hash as a byte slice
func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashString calculates the SHA-256 hash of a string
// Returns the resulting hash as a byte slice
func HashString(s string) []byte {
	return Hash([]byte(s))
}

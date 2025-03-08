package storage

import (
	"errors"
)

var (
	// ErrKeyNotFound is returned when the requested key is not found in the database
	ErrKeyNotFound = errors.New("key not found")

	// ErrDatabaseClosed is returned when operations are attempted on a closed database
	ErrDatabaseClosed = errors.New("database already closed")

	// ErrBatchCommitFailed is returned when a batch commit operation fails
	ErrBatchCommitFailed = errors.New("batch commit failed")
)

// DB defines the interface for database operations
type DB interface {
	// Put stores a key-value pair in the database
	Put(key []byte, value []byte) error

	// Get retrieves the value for a given key
	// Returns ErrKeyNotFound if the key doesn't exist
	Get(key []byte) ([]byte, error)

	// Has returns whether the key exists in the database
	Has(key []byte) (bool, error)

	// Delete removes a key-value pair from the database
	Delete(key []byte) error

	// NewBatch creates a new batch operation
	NewBatch() Batch

	// NewIterator creates a new iterator over a specific key range
	// If start is nil, it starts from the beginning
	// If end is nil, it iterates until the end
	NewIterator(start, end []byte) Iterator

	// Close releases all database resources
	Close() error
}

// Batch represents a group of operations to be performed atomically
type Batch interface {
	// Put adds a key-value pair to the batch
	Put(key []byte, value []byte) error

	// Delete adds a key deletion to the batch
	Delete(key []byte) error

	// ValueSize returns the total size of all values in the batch
	ValueSize() int

	// Reset clears all operations from the batch
	Reset()

	// Write commits the batch to the database
	Write() error
}

// Iterator allows iterating over a range of key-value pairs
type Iterator interface {
	// Next moves the iterator to the next key-value pair
	// Returns false when the end is reached
	Next() bool

	// Key returns the current key
	Key() []byte

	// Value returns the current value
	Value() []byte

	// Error returns any accumulated error
	Error() error

	// Release releases associated resources
	Release()
}

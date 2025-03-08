package storage

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDBStore implements the DB interface using LevelDB
type LevelDBStore struct {
	db   *leveldb.DB
	path string
	mu   sync.RWMutex
}

// NewLevelDBStore creates a new LevelDB storage instance
func NewLevelDBStore(path string) (*LevelDBStore, error) {
	// Ensure directory exists
	if err := ensureDir(path); err != nil {
		return nil, err
	}

	// Default LevelDB options
	options := &opt.Options{
		OpenFilesCacheCapacity: 16,
		BlockCacheCapacity:     16 * 1024 * 1024, // 16MB
		WriteBuffer:            32 * 1024 * 1024, // 32MB
		Filter:                 filter.NewBloomFilter(10),
	}

	// Open the database
	db, err := leveldb.OpenFile(path, options)
	if err != nil {
		// If database is corrupted, attempt to recover
		if isCorrupted(err) {
			db, err = leveldb.RecoverFile(path, options)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return &LevelDBStore{
		db:   db,
		path: path,
	}, nil
}

// Put stores a key-value pair in the database
func (store *LevelDBStore) Put(key []byte, value []byte) error {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return ErrDatabaseClosed
	}

	return store.db.Put(key, value, nil)
}

// Get retrieves the value for a given key
func (store *LevelDBStore) Get(key []byte) ([]byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return nil, ErrDatabaseClosed
	}

	value, err := store.db.Get(key, nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	return value, nil
}

// Has returns whether the key exists in the database
func (store *LevelDBStore) Has(key []byte) (bool, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return false, ErrDatabaseClosed
	}

	return store.db.Has(key, nil)
}

// Delete removes a key-value pair from the database
func (store *LevelDBStore) Delete(key []byte) error {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return ErrDatabaseClosed
	}

	return store.db.Delete(key, nil)
}

// NewBatch creates a new batch operation
func (store *LevelDBStore) NewBatch() Batch {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return nil
	}

	return &levelDBBatch{
		batch:  leveldb.Batch{},
		db:     store.db,
		parent: store,
	}
}

// NewIterator creates a new iterator over a specific key range
func (store *LevelDBStore) NewIterator(start, end []byte) Iterator {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if store.db == nil {
		return nil
	}

	var r *util.Range
	if start != nil || end != nil {
		r = &util.Range{Start: start, Limit: end}
	}

	return &levelDBIterator{
		iter:   store.db.NewIterator(r, nil),
		parent: store,
	}
}

// Close releases all database resources
func (store *LevelDBStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()

	if store.db == nil {
		return ErrDatabaseClosed
	}

	err := store.db.Close()
	store.db = nil
	return err
}

// levelDBBatch implements the Batch interface for LevelDB
type levelDBBatch struct {
	batch  leveldb.Batch
	db     *leveldb.DB
	parent *LevelDBStore
}

// Put adds a key-value pair to the batch
func (b *levelDBBatch) Put(key []byte, value []byte) error {
	b.parent.mu.RLock()
	defer b.parent.mu.RUnlock()

	if b.parent.db == nil {
		return ErrDatabaseClosed
	}

	b.batch.Put(key, value)
	return nil
}

// Delete adds a key deletion to the batch
func (b *levelDBBatch) Delete(key []byte) error {
	b.parent.mu.RLock()
	defer b.parent.mu.RUnlock()

	if b.parent.db == nil {
		return ErrDatabaseClosed
	}

	b.batch.Delete(key)
	return nil
}

// ValueSize returns the total size of all values in the batch
func (b *levelDBBatch) ValueSize() int {
	return b.batch.Len()
}

// Reset clears all operations from the batch
func (b *levelDBBatch) Reset() {
	b.batch.Reset()
}

// Write commits the batch to the database
func (b *levelDBBatch) Write() error {
	b.parent.mu.RLock()
	defer b.parent.mu.RUnlock()

	if b.parent.db == nil {
		return ErrDatabaseClosed
	}

	return b.parent.db.Write(&b.batch, nil)
}

// levelDBIterator implements the Iterator interface for LevelDB
type levelDBIterator struct {
	iter   iterator.Iterator
	parent *LevelDBStore
}

// Next moves the iterator to the next key-value pair
func (it *levelDBIterator) Next() bool {
	return it.iter.Next()
}

// Key returns the current key
func (it *levelDBIterator) Key() []byte {
	return it.iter.Key()
}

// Value returns the current value
func (it *levelDBIterator) Value() []byte {
	return it.iter.Value()
}

// Error returns any accumulated error
func (it *levelDBIterator) Error() error {
	return it.iter.Error()
}

// Release releases associated resources
func (it *levelDBIterator) Release() {
	it.iter.Release()
}

// Helper functions

// ensureDir makes sure the directory exists
func ensureDir(path string) error {
	dirPath := filepath.Dir(path)
	return os.MkdirAll(dirPath, 0750)
}

// isCorrupted determines if the error indicates a corrupted database
func isCorrupted(err error) bool {
	if err == nil {
		return false
	}

	_, isCorrupted := err.(*errors.ErrCorrupted)
	return isCorrupted
}

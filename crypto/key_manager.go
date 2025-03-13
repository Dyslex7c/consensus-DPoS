package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyManager handles storage and retrieval of cryptographic keys
type KeyManager struct {
	keyDir string
	keys   map[string]*KeyPair
}

// NewKeyManager creates a new key manager that stores keys in the specified directory
func NewKeyManager(keyDir string) (*KeyManager, error) {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	km := &KeyManager{
		keyDir: keyDir,
		keys:   make(map[string]*KeyPair),
	}

	// Load any existing keys
	if err := km.loadKeys(); err != nil {
		return nil, err
	}

	return km, nil
}

// loadKeys loads all keys from the key directory
func (km *KeyManager) loadKeys() error {
	files, err := os.ReadDir(km.keyDir)
	if err != nil {
		return fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".key") {
			continue
		}

		keyPath := filepath.Join(km.keyDir, file.Name())
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", file.Name(), err)
		}

		keyPair, err := LoadKeyPair(keyData)
		if err != nil {
			return fmt.Errorf("failed to load key from %s: %w", file.Name(), err)
		}

		// Use the filename without .key as the key ID
		keyID := strings.TrimSuffix(file.Name(), ".key")
		km.keys[keyID] = keyPair
	}

	return nil
}

// CreateKey generates a new key pair and stores it with the given ID
func (km *KeyManager) CreateKey(keyID string) (*KeyPair, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Store the key in memory
	km.keys[keyID] = keyPair

	// Write the key to disk
	keyPath := filepath.Join(km.keyDir, keyID+".key")
	if err := os.WriteFile(keyPath, keyPair.PrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return keyPair, nil
}

// GetKey retrieves a key pair by ID
func (km *KeyManager) GetKey(keyID string) (*KeyPair, bool) {
	keyPair, exists := km.keys[keyID]
	return keyPair, exists
}

// ListKeys returns a list of all key IDs
func (km *KeyManager) ListKeys() []string {
	var keyIDs []string
	for keyID := range km.keys {
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}

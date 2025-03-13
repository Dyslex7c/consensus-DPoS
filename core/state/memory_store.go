package state

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/crypto"
	"github.com/Dyslex7c/consensus-DPoS/storage"
)

var (
	ErrInsufficientBalance     = errors.New("insufficient balance")
	ErrAccountNotFound         = errors.New("account not found")
	ErrValidatorNotFound       = errors.New("validator not found")
	ErrValidatorExists         = errors.New("validator already exists")
	ErrStakeNotFound           = errors.New("stake not found")
	ErrStakeExists             = errors.New("stake already exists")
	ErrTransactionAlreadySeen  = errors.New("transaction already processed")
	ErrInvalidValidatorAddress = errors.New("invalid validator address")
)

// MemoryStore implements StateStore with persistent backing
type MemoryStore struct {
	mu sync.RWMutex
	db storage.DB

	// Account balances
	balances map[string]uint64

	// Validator state
	validators map[string]*types.Validator

	// Staking state
	stakes                 map[string]*types.Stake // key: delegator+validator
	validatorTotalStakes   map[string]uint64       // key: validator address
	delegatorStakesIndices map[string][]string     // key: delegator address, value: array of stake keys

	// Block state
	latestBlockHeight uint64
	latestBlockHash   []byte

	// Transaction state
	processedTxs map[string]struct{}
}

// NewMemoryStore creates a new memory state store with database backing
func NewMemoryStore(db storage.DB) *MemoryStore {
	return &MemoryStore{
		db:                     db,
		balances:               make(map[string]uint64),
		validators:             make(map[string]*types.Validator),
		stakes:                 make(map[string]*types.Stake),
		validatorTotalStakes:   make(map[string]uint64),
		delegatorStakesIndices: make(map[string][]string),
		processedTxs:           make(map[string]struct{}),
	}
}

// Initialize loads state from the database
func (m *MemoryStore) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load balances
	balancesData, err := m.db.Get([]byte("balances"))
	if err == nil {
		// Deserialize balances data
		// Implementation depends on your serialization format
		// This is a placeholder
	}

	// Load validators
	validatorsData, err := m.db.Get([]byte("validators"))
	if err == nil {
		// Deserialize validators data
	}

	// Load stakes
	stakesData, err := m.db.Get([]byte("stakes"))
	if err == nil {
		// Deserialize stakes data
	}

	// Load block state
	blockHeightData, err := m.db.Get([]byte("latest_block_height"))
	if err == nil {
		// Parse block height
	}

	blockHashData, err := m.db.Get([]byte("latest_block_hash"))
	if err == nil {
		m.latestBlockHash = blockHashData
	}

	// Load processed transactions
	// This might be too large for a single key-value pair
	// Consider using a prefix scan instead

	return nil
}

// Helper to create a stake key
func makeStakeKey(delegator, validator []byte) string {
	return fmt.Sprintf("%s:%s", crypto.HashToHex(delegator), crypto.HashToHex(validator))
}

// Account methods

func (m *MemoryStore) GetBalance(address []byte) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := crypto.HashToHex(address)
	return m.balances[key], nil // Returns 0 if not found
}

func (m *MemoryStore) SetBalance(address []byte, amount uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := crypto.HashToHex(address)
	m.balances[key] = amount
	return nil
}

func (m *MemoryStore) TransferBalance(from, to []byte, amount uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fromKey := crypto.HashToHex(from)
	toKey := crypto.HashToHex(to)

	fromBalance := m.balances[fromKey]
	if fromBalance < amount {
		return ErrInsufficientBalance
	}

	m.balances[fromKey] = fromBalance - amount
	m.balances[toKey] = m.balances[toKey] + amount

	return nil
}

// Validator methods

func (m *MemoryStore) GetValidators() ([]*types.Validator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validators := make([]*types.Validator, 0, len(m.validators))
	for _, validator := range m.validators {
		validators = append(validators, validator.Clone())
	}

	return validators, nil
}

func (m *MemoryStore) GetValidator(address []byte) (*types.Validator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := crypto.HashToHex(address)
	validator, exists := m.validators[key]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	return validator.Clone(), nil
}

func (m *MemoryStore) AddValidator(validator *types.Validator) error {
	if validator == nil || len(validator.Address) == 0 {
		return ErrInvalidValidatorAddress
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := crypto.HashToHex(validator.Address)
	if _, exists := m.validators[key]; exists {
		return ErrValidatorExists
	}

	m.validators[key] = validator.Clone()
	return nil
}

func (m *MemoryStore) UpdateValidator(validator *types.Validator) error {
	if validator == nil || len(validator.Address) == 0 {
		return ErrInvalidValidatorAddress
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := crypto.HashToHex(validator.Address)
	if _, exists := m.validators[key]; !exists {
		return ErrValidatorNotFound
	}

	m.validators[key] = validator.Clone()
	return nil
}

func (m *MemoryStore) RemoveValidator(address []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := crypto.HashToHex(address)
	if _, exists := m.validators[key]; !exists {
		return ErrValidatorNotFound
	}

	delete(m.validators, key)
	return nil
}

// Stake methods

func (m *MemoryStore) GetTotalStake() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total uint64
	for _, stake := range m.stakes {
		total += stake.Amount
	}

	return total, nil
}

func (m *MemoryStore) GetStake(delegator, validator []byte) (*types.Stake, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := makeStakeKey(delegator, validator)
	stake, exists := m.stakes[key]
	if !exists {
		return nil, ErrStakeNotFound
	}

	return stake.Clone(), nil
}

func (m *MemoryStore) AddStake(stake *types.Stake) error {
	if stake == nil {
		return errors.New("stake cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeStakeKey(stake.Delegator, stake.Validator)
	if _, exists := m.stakes[key]; exists {
		return ErrStakeExists
	}

	// Store the stake
	m.stakes[key] = stake.Clone()

	// Update validator total stake
	validatorKey := crypto.HashToHex(stake.Validator)
	m.validatorTotalStakes[validatorKey] += stake.Amount

	// Update delegator indices
	delegatorKey := crypto.HashToHex(stake.Delegator)
	m.delegatorStakesIndices[delegatorKey] = append(
		m.delegatorStakesIndices[delegatorKey],
		key,
	)

	return nil
}

func (m *MemoryStore) UpdateStake(stake *types.Stake) error {
	if stake == nil {
		return errors.New("stake cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeStakeKey(stake.Delegator, stake.Validator)
	existingStake, exists := m.stakes[key]
	if !exists {
		return ErrStakeNotFound
	}

	// Update validator total stake
	validatorKey := crypto.HashToHex(stake.Validator)
	m.validatorTotalStakes[validatorKey] -= existingStake.Amount
	m.validatorTotalStakes[validatorKey] += stake.Amount

	// Update the stake
	m.stakes[key] = stake.Clone()

	return nil
}

func (m *MemoryStore) RemoveStake(delegator, validator []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeStakeKey(delegator, validator)
	existingStake, exists := m.stakes[key]
	if !exists {
		return ErrStakeNotFound
	}

	// Update validator total stake
	validatorKey := crypto.HashToHex(validator)
	m.validatorTotalStakes[validatorKey] -= existingStake.Amount

	// Remove from delegator indices
	delegatorKey := crypto.HashToHex(delegator)
	indices := m.delegatorStakesIndices[delegatorKey]
	for i, idx := range indices {
		if idx == key {
			// Remove index by swapping with the last element and truncating
			indices[i] = indices[len(indices)-1]
			m.delegatorStakesIndices[delegatorKey] = indices[:len(indices)-1]
			break
		}
	}

	// If no more stakes for this delegator, remove the entry
	if len(m.delegatorStakesIndices[delegatorKey]) == 0 {
		delete(m.delegatorStakesIndices, delegatorKey)
	}

	// Delete the stake
	delete(m.stakes, key)

	return nil
}

func (m *MemoryStore) GetValidatorTotalStake(validator []byte) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validatorKey := crypto.HashToHex(validator)
	return m.validatorTotalStakes[validatorKey], nil
}

func (m *MemoryStore) GetDelegatorStakes(delegator []byte) ([]*types.Stake, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	delegatorKey := crypto.HashToHex(delegator)
	indices := m.delegatorStakesIndices[delegatorKey]

	stakes := make([]*types.Stake, 0, len(indices))
	for _, key := range indices {
		if stake, exists := m.stakes[key]; exists {
			stakes = append(stakes, stake.Clone())
		}
	}

	return stakes, nil
}

// Block state methods

func (m *MemoryStore) GetLatestBlockHeight() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.latestBlockHeight, nil
}

func (m *MemoryStore) SetLatestBlockHeight(height uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.latestBlockHeight = height
	return nil
}

func (m *MemoryStore) GetLatestBlockHash() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.latestBlockHash == nil {
		return nil, nil
	}

	hashCopy := make([]byte, len(m.latestBlockHash))
	copy(hashCopy, m.latestBlockHash)
	return hashCopy, nil
}

func (m *MemoryStore) SetLatestBlockHash(hash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hash == nil {
		m.latestBlockHash = nil
		return nil
	}

	m.latestBlockHash = make([]byte, len(hash))
	copy(m.latestBlockHash, hash)
	return nil
}

// Transaction methods

func (m *MemoryStore) GetProcessedTransaction(txID []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.processedTxs[string(txID)]
	return exists, nil
}

func (m *MemoryStore) MarkTransactionProcessed(txID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.processedTxs[string(txID)] = struct{}{}
	return nil
}

// State operation methods

func (m *MemoryStore) Commit() error {
	// Persist current state to the database
	m.mu.Lock()
	defer m.mu.Unlock()

	// Serialize and save balances
	// Implementation depends on your serialization format

	// Serialize and save validators

	// Serialize and save stakes

	// Save block state
	if m.latestBlockHeight > 0 {
		// Save latest block height
	}

	if m.latestBlockHash != nil {
		err := m.db.Put([]byte("latest_block_hash"), m.latestBlockHash)
		if err != nil {
			return err
		}
	}

	// Save processed transactions
	// This might be too large for a single key-value pair
	// Consider using batches or multiple keys

	return nil
}

func (m *MemoryStore) Rollback() error {
	// Reload state from the last committed state in the database
	return m.Initialize()
}

func (m *MemoryStore) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.balances = make(map[string]uint64)
	m.validators = make(map[string]*types.Validator)
	m.stakes = make(map[string]*types.Stake)
	m.validatorTotalStakes = make(map[string]uint64)
	m.delegatorStakesIndices = make(map[string][]string)
	m.processedTxs = make(map[string]struct{})
	m.latestBlockHeight = 0
	m.latestBlockHash = nil

	// Clear database
	// This is a placeholder. You might want to implement this differently

	return nil
}

// Clone makes a deep copy of the state store
func (m *MemoryStore) Clone() (StateStore, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clone := NewMemoryStore(m.db)

	// Copy balances
	for k, v := range m.balances {
		clone.balances[k] = v
	}

	// Copy validators
	for k, v := range m.validators {
		clone.validators[k] = v.Clone()
	}

	// Copy stakes
	for k, v := range m.stakes {
		clone.stakes[k] = v.Clone()
	}

	// Copy validator total stakes
	for k, v := range m.validatorTotalStakes {
		clone.validatorTotalStakes[k] = v
	}

	// Copy delegator stakes indices
	for k, v := range m.delegatorStakesIndices {
		indices := make([]string, len(v))
		copy(indices, v)
		clone.delegatorStakesIndices[k] = indices
	}

	// Copy processed transactions
	for k := range m.processedTxs {
		clone.processedTxs[k] = struct{}{}
	}

	// Copy block state
	clone.latestBlockHeight = m.latestBlockHeight
	if m.latestBlockHash != nil {
		clone.latestBlockHash = make([]byte, len(m.latestBlockHash))
		copy(clone.latestBlockHash, m.latestBlockHash)
	}

	return clone, nil
}

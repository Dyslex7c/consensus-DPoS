package state

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

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

	// Initialize maps if nil
	if m.balances == nil {
		m.balances = make(map[string]uint64)
	}
	if m.validators == nil {
		m.validators = make(map[string]*types.Validator)
	}
	if m.stakes == nil {
		m.stakes = make(map[string]*types.Stake)
	}
	if m.validatorTotalStakes == nil {
		m.validatorTotalStakes = make(map[string]uint64)
	}
	if m.delegatorStakesIndices == nil {
		m.delegatorStakesIndices = make(map[string][]string)
	}
	if m.processedTxs == nil {
		m.processedTxs = make(map[string]struct{})
	}

	// Load balances using a prefix iterator
	balanceIterator := m.db.NewIterator([]byte("balance:"), []byte("balance:\xff"))
	defer balanceIterator.Release()

	for balanceIterator.Next() {
		key := string(balanceIterator.Key()[len("balance:"):]) // Remove prefix
		var balance uint64
		buf := balanceIterator.Value()
		if len(buf) == 8 {
			// Assuming uint64 stored as 8 bytes in big-endian
			balance = uint64(buf[0])<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32 |
				uint64(buf[4])<<24 | uint64(buf[5])<<16 | uint64(buf[6])<<8 | uint64(buf[7])
			m.balances[key] = balance
		}
	}

	if err := balanceIterator.Error(); err != nil {
		return err
	}

	// Load validators
	validatorIterator := m.db.NewIterator([]byte("validator:"), []byte("validator:\xff"))
	defer validatorIterator.Release()

	for validatorIterator.Next() {
		key := string(validatorIterator.Key()[len("validator:"):]) // Remove prefix
		data := validatorIterator.Value()

		// Deserialize validator
		validator := &types.Validator{}
		if err := deserializeValidator(data, validator); err != nil {
			return err
		}

		m.validators[key] = validator
	}

	if err := validatorIterator.Error(); err != nil {
		return err
	}

	// Load stakes
	stakeIterator := m.db.NewIterator([]byte("stake:"), []byte("stake:\xff"))
	defer stakeIterator.Release()

	for stakeIterator.Next() {
		key := string(stakeIterator.Key()[len("stake:"):]) // Remove prefix
		data := stakeIterator.Value()

		// Deserialize stake
		stake := &types.Stake{}
		if err := deserializeStake(data, stake); err != nil {
			return err
		}

		m.stakes[key] = stake

		// Update validator total stakes
		validatorKey := crypto.HashToHex(stake.Validator)
		m.validatorTotalStakes[validatorKey] += stake.Amount

		// Update delegator indices
		delegatorKey := crypto.HashToHex(stake.Delegator)
		m.delegatorStakesIndices[delegatorKey] = append(
			m.delegatorStakesIndices[delegatorKey],
			key,
		)
	}

	if err := stakeIterator.Error(); err != nil {
		return err
	}

	// Load block height
	blockHeightData, err := m.db.Get([]byte("latest_block_height"))
	if err == nil && len(blockHeightData) == 8 {
		m.latestBlockHeight = uint64(blockHeightData[0])<<56 | uint64(blockHeightData[1])<<48 |
			uint64(blockHeightData[2])<<40 | uint64(blockHeightData[3])<<32 |
			uint64(blockHeightData[4])<<24 | uint64(blockHeightData[5])<<16 |
			uint64(blockHeightData[6])<<8 | uint64(blockHeightData[7])
	} else if err != nil && err != storage.ErrKeyNotFound {
		return err
	}

	// Load block hash
	blockHashData, err := m.db.Get([]byte("latest_block_hash"))
	if err == nil {
		m.latestBlockHash = make([]byte, len(blockHashData))
		copy(m.latestBlockHash, blockHashData)
	} else if err != nil && err != storage.ErrKeyNotFound {
		return err
	}

	// Load processed transactions using iterator with prefix
	txIterator := m.db.NewIterator([]byte("tx:"), []byte("tx:\xff"))
	defer txIterator.Release()

	for txIterator.Next() {
		txID := string(txIterator.Key()[len("tx:"):]) // Remove prefix
		m.processedTxs[txID] = struct{}{}
	}

	if err := txIterator.Error(); err != nil {
		return err
	}

	return nil
}

// Helper function to deserialize a validator
func deserializeValidator(data []byte, validator *types.Validator) error {
	if len(data) < 8 { // Minimum size check
		return errors.New("invalid validator data: too short")
	}

	offset := 0

	// Read Address length and data
	if offset+4 > len(data) {
		return errors.New("invalid validator data: address length")
	}
	addrLen := int(uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	offset += 4

	if offset+addrLen > len(data) {
		return errors.New("invalid validator data: address data")
	}
	validator.Address = make([]byte, addrLen)
	copy(validator.Address, data[offset:offset+addrLen])
	offset += addrLen

	// Read PublicKey length and data
	if offset+4 > len(data) {
		return errors.New("invalid validator data: public key length")
	}
	pubKeyLen := int(uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	offset += 4

	if offset+pubKeyLen > len(data) {
		return errors.New("invalid validator data: public key data")
	}
	validator.PublicKey = make([]byte, pubKeyLen)
	copy(validator.PublicKey, data[offset:offset+pubKeyLen])
	offset += pubKeyLen

	// Read VotingPower (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid validator data: voting power")
	}
	validator.VotingPower = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read TotalStake (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid validator data: total stake")
	}
	validator.TotalStake = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read SelfStake (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid validator data: self stake")
	}
	validator.SelfStake = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read Commission (uint8)
	if offset+1 > len(data) {
		return errors.New("invalid validator data: commission")
	}
	validator.Commission = data[offset]
	offset += 1

	// Read JoinedAt (time.Time) as Unix timestamp
	if offset+8 > len(data) {
		return errors.New("invalid validator data: joined at")
	}
	joinedAtUnix := int64(uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7]))
	validator.JoinedAt = time.Unix(joinedAtUnix, 0)
	offset += 8

	// Read Status (ValidatorStatus - uint8)
	if offset+1 > len(data) {
		return errors.New("invalid validator data: status")
	}
	validator.Status = types.ValidatorStatus(data[offset])
	offset += 1

	// Read Uptime (float64) - stored as bits of float64
	if offset+8 > len(data) {
		return errors.New("invalid validator data: uptime")
	}
	uptimeBits := uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	validator.Uptime = math.Float64frombits(uptimeBits)
	offset += 8

	// Read BlocksProposed (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid validator data: blocks proposed")
	}
	validator.BlocksProposed = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read BlocksValidated (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid validator data: blocks validated")
	}
	validator.BlocksValidated = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read JailedUntil (time.Time) as Unix timestamp
	if offset+8 > len(data) {
		return errors.New("invalid validator data: jailed until")
	}
	jailedUntilUnix := int64(uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7]))
	validator.JailedUntil = time.Unix(jailedUntilUnix, 0)
	offset += 8

	// Read MissedBlocksCounter (uint32)
	if offset+4 > len(data) {
		return errors.New("invalid validator data: missed blocks counter")
	}
	validator.MissedBlocksCounter = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
	offset += 4

	return nil
}

// Helper function to deserialize a stake
// Helper function to deserialize a stake
func deserializeStake(data []byte, stake *types.Stake) error {
	if len(data) < 8 { // Minimum size check
		return errors.New("invalid stake data: too short")
	}

	offset := 0

	// Read Delegator length and data
	if offset+4 > len(data) {
		return errors.New("invalid stake data: delegator length")
	}
	delegatorLen := int(uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	offset += 4

	if offset+delegatorLen > len(data) {
		return errors.New("invalid stake data: delegator data")
	}
	stake.Delegator = make([]byte, delegatorLen)
	copy(stake.Delegator, data[offset:offset+delegatorLen])
	offset += delegatorLen

	// Read Validator length and data
	if offset+4 > len(data) {
		return errors.New("invalid stake data: validator length")
	}
	validatorLen := int(uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	offset += 4

	if offset+validatorLen > len(data) {
		return errors.New("invalid stake data: validator data")
	}
	stake.Validator = make([]byte, validatorLen)
	copy(stake.Validator, data[offset:offset+validatorLen])
	offset += validatorLen

	// Read Amount (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid stake data: amount")
	}
	stake.Amount = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read CreatedAt (time.Time) as Unix timestamp
	if offset+8 > len(data) {
		return errors.New("invalid stake data: created at")
	}
	createdAtUnix := int64(uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7]))
	stake.CreatedAt = time.Unix(createdAtUnix, 0)
	offset += 8

	// Read UpdatedAt (time.Time) as Unix timestamp
	if offset+8 > len(data) {
		return errors.New("invalid stake data: updated at")
	}
	updatedAtUnix := int64(uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7]))
	stake.UpdatedAt = time.Unix(updatedAtUnix, 0)
	offset += 8

	// Read PendingRewards (uint64)
	if offset+8 > len(data) {
		return errors.New("invalid stake data: pending rewards")
	}
	stake.PendingRewards = uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7])
	offset += 8

	// Read Unbonding (bool) - stored as a byte
	if offset+1 > len(data) {
		return errors.New("invalid stake data: unbonding")
	}
	stake.Unbonding = data[offset] != 0
	offset += 1

	// Read UnbondingCompleteAt (time.Time) as Unix timestamp
	if offset+8 > len(data) {
		return errors.New("invalid stake data: unbonding complete at")
	}
	unbondingCompleteAtUnix := int64(uint64(data[offset])<<56 | uint64(data[offset+1])<<48 | uint64(data[offset+2])<<40 | uint64(data[offset+3])<<32 |
		uint64(data[offset+4])<<24 | uint64(data[offset+5])<<16 | uint64(data[offset+6])<<8 | uint64(data[offset+7]))
	stake.UnbondingCompleteAt = time.Unix(unbondingCompleteAtUnix, 0)
	offset += 8

	return nil
}

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

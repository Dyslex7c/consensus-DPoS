package consensus

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// DefaultValidatorManagerConfig returns the default configuration
func DefaultValidatorManagerConfig() *ValidatorManagerConfig {
	return &ValidatorManagerConfig{
		MaxValidators:          100,
		ActiveValidatorsCount:  21,
		MinStake:               1000,
		UnbondingTime:          14 * 24 * time.Hour, // 14 days
		SlashingPenaltyPercent: 5,                   // 5% of stake
		JailTime:               48 * time.Hour,      // 48 hours
	}
}

// ValidatorManagerConfig holds configuration for the validator manager
type ValidatorManagerConfig struct {
	MaxValidators          int
	ActiveValidatorsCount  int
	MinStake               uint64
	UnbondingTime          time.Duration
	SlashingPenaltyPercent int
	JailTime               time.Duration
}

// ValidatorManagerImpl implements the ValidatorManager interface
type ValidatorManagerImpl struct {
	config       *ValidatorManagerConfig
	validators   map[string]*types.Validator
	activeSet    []*types.Validator
	inactiveSet  []*types.Validator
	jailedSet    map[string]*types.Validator
	stakeManager StakeManager
	storage      Storage
	mutex        sync.RWMutex
	currentEpoch uint64
	logger       *utils.Logger
}

// Storage interface for persistence
type Storage interface {
	SaveValidators([]*types.Validator) error
	LoadValidators() ([]*types.Validator, error)
}

// NewValidatorManager creates a new validator manager
func NewValidatorManager(
	config *ValidatorManagerConfig,
	stakeManager StakeManager,
	storage Storage,
	logger *utils.Logger,
) *ValidatorManagerImpl {
	if config == nil {
		config = DefaultValidatorManagerConfig()
	}

	return &ValidatorManagerImpl{
		config:       config,
		validators:   make(map[string]*types.Validator),
		activeSet:    make([]*types.Validator, 0, config.ActiveValidatorsCount),
		inactiveSet:  make([]*types.Validator, 0),
		jailedSet:    make(map[string]*types.Validator),
		stakeManager: stakeManager,
		storage:      storage,
		currentEpoch: 0,
		logger:       logger,
	}
}

// Initialize loads validators from storage
func (vm *ValidatorManagerImpl) Initialize() error {
	validators, err := vm.storage.LoadValidators()
	if err != nil {
		return fmt.Errorf("failed to load validators: %w", err)
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	for _, v := range validators {
		vm.validators[BytesToString(v.PublicKey)] = v
	}

	// Sort validators by stake and select active set
	return vm.updateValidatorSets()
}

// GetValidators returns all validators
func (vm *ValidatorManagerImpl) GetValidators() ([]*types.Validator, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	validators := make([]*types.Validator, 0, len(vm.validators))
	for _, v := range vm.validators {
		validators = append(validators, v)
	}

	return validators, nil
}

// GetActiveValidators returns the active validator set
// Updated to match the interface definition
func (vm *ValidatorManagerImpl) GetActiveValidators() ([]types.Validator, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// Create a slice of types.Validator (not pointers) to match the interface
	result := make([]types.Validator, len(vm.activeSet))
	for i, v := range vm.activeSet {
		result[i] = *v // Dereference the pointer to copy the value
	}

	return result, nil
}

// GetValidatorByPublicKey returns a validator by their public key
// Added to match the interface definition
func (vm *ValidatorManagerImpl) GetValidatorByPublicKey(publicKey []byte) (*types.Validator, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	pkStr := BytesToString(publicKey)
	validator, exists := vm.validators[pkStr]
	if !exists {
		return nil, fmt.Errorf("validator not found")
	}

	return validator, nil
}

// IsValidator checks if a public key belongs to a validator
func (vm *ValidatorManagerImpl) IsValidator(publicKey []byte) (bool, error) {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	pkStr := BytesToString(publicKey)
	_, exists := vm.validators[pkStr]

	return exists, nil
}

// RegisterValidator registers a new validator
func (vm *ValidatorManagerImpl) RegisterValidator(validator *types.Validator) error {
	if validator == nil || validator.PublicKey == nil {
		return fmt.Errorf("invalid validator")
	}

	// Check minimum stake requirement
	if validator.SelfStake < vm.config.MinStake {
		return fmt.Errorf("validator stake %d is below minimum requirement %d",
			validator.SelfStake, vm.config.MinStake)
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if the validator already exists
	pkStr := BytesToString(validator.PublicKey)
	if _, exists := vm.validators[pkStr]; exists {
		return fmt.Errorf("validator already registered")
	}

	// Initialize validator fields if not set
	if validator.Status == 0 {
		validator.Status = types.ValidatorStatusInactive
	}
	if validator.JoinedAt.IsZero() {
		validator.JoinedAt = time.Now()
	}

	// Add the validator
	vm.validators[pkStr] = validator

	// Update validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		delete(vm.validators, pkStr)
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		delete(vm.validators, pkStr)
		_ = vm.updateValidatorSets()
		return fmt.Errorf("failed to save validators: %w", err)
	}

	vm.logger.Info("Validator registered", "publicKey", pkStr)

	return nil
}

// UpdateValidator updates an existing validator
func (vm *ValidatorManagerImpl) UpdateValidator(validator *types.Validator) error {
	if validator == nil || validator.PublicKey == nil {
		return fmt.Errorf("invalid validator")
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Check if the validator exists
	pkStr := BytesToString(validator.PublicKey)
	if _, exists := vm.validators[pkStr]; !exists {
		return fmt.Errorf("validator not found")
	}

	// Update the validator
	vm.validators[pkStr] = validator

	// Update validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	vm.logger.Info("Validator updated", "publicKey", pkStr)

	return nil
}

// RemoveValidator removes a validator
func (vm *ValidatorManagerImpl) RemoveValidator(publicKey []byte) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	pkStr := BytesToString(publicKey)
	if _, exists := vm.validators[pkStr]; !exists {
		return fmt.Errorf("validator not found")
	}

	// Delete the validator
	delete(vm.validators, pkStr)

	// Update validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	vm.logger.Info("Validator removed", "publicKey", pkStr)

	return nil
}

// RotateValidators performs the validator rotation at epoch boundaries
func (vm *ValidatorManagerImpl) RotateValidators(epoch uint64) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// Skip if we're already at this epoch
	if vm.currentEpoch == epoch {
		return nil
	}

	vm.logger.Info("Rotating validators", "epoch", epoch)

	// Set the current epoch
	vm.currentEpoch = epoch

	// Check for validators ready to be unjailed
	now := time.Now()
	for pkStr, validator := range vm.jailedSet {
		if validator.JailedUntil.Before(now) {
			vm.logger.Info("Unjailing validator", "publicKey", pkStr)
			validator.Status = types.ValidatorStatusInactive
			delete(vm.jailedSet, pkStr)
		}
	}

	// Update the validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	// Log the new active set
	vm.logActiveValidators()

	return nil
}

// SlashValidator applies slashing penalties to a validator
func (vm *ValidatorManagerImpl) SlashValidator(publicKey []byte, reason string, amount uint64) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	pkStr := BytesToString(publicKey)
	validator, exists := vm.validators[pkStr]
	if !exists {
		return fmt.Errorf("validator not found")
	}

	// Calculate slash amount
	slashAmount := amount
	if slashAmount == 0 {
		// Use percentage-based slashing
		slashAmount = validator.SelfStake * uint64(vm.config.SlashingPenaltyPercent) / 100
	}

	vm.logger.Info("Slashing validator",
		"publicKey", pkStr,
		"reason", reason,
		"amount", slashAmount,
		"oldStake", validator.SelfStake)

	// Apply the slashing
	if slashAmount > validator.SelfStake {
		slashAmount = validator.SelfStake
	}

	validator.SelfStake -= slashAmount
	// Update total stake
	validator.TotalStake = validator.SelfStake

	// Try to get delegated stake from stake manager
	delegatedStake, err := vm.stakeManager.GetDelegatedStake(validator.PublicKey)
	if err == nil {
		validator.TotalStake += delegatedStake
	}

	// Update voting power based on total stake
	validator.VotingPower = validator.TotalStake

	// If stake falls below minimum, remove from active set
	if validator.SelfStake < vm.config.MinStake {
		validator.Status = types.ValidatorStatusInactive
	}

	// Update validator sets
	err = vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	return nil
}

// JailValidator jails a validator for a specified duration
func (vm *ValidatorManagerImpl) JailValidator(publicKey []byte, duration uint64) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	pkStr := BytesToString(publicKey)
	validator, exists := vm.validators[pkStr]
	if !exists {
		return fmt.Errorf("validator not found")
	}

	// Set jail duration
	jailDuration := time.Duration(duration) * time.Second
	if jailDuration == 0 {
		jailDuration = vm.config.JailTime
	}

	vm.logger.Info("Jailing validator",
		"publicKey", pkStr,
		"duration", jailDuration.String())

	// Update validator status
	validator.Status = types.ValidatorStatusJailed
	validator.JailedUntil = time.Now().Add(jailDuration)

	// Add to jailed set
	vm.jailedSet[pkStr] = validator

	// Update validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	return nil
}

// UnjailValidator releases a validator from jail
func (vm *ValidatorManagerImpl) UnjailValidator(publicKey []byte) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	pkStr := BytesToString(publicKey)
	validator, exists := vm.validators[pkStr]
	if !exists {
		return fmt.Errorf("validator not found")
	}

	if validator.Status != types.ValidatorStatusJailed {
		return fmt.Errorf("validator is not jailed")
	}

	vm.logger.Info("Unjailing validator", "publicKey", pkStr)

	// Update validator status
	validator.Status = types.ValidatorStatusInactive
	validator.JailedUntil = time.Time{}

	// Remove from jailed set
	delete(vm.jailedSet, pkStr)

	// Update validator sets
	err := vm.updateValidatorSets()
	if err != nil {
		return fmt.Errorf("failed to update validator sets: %w", err)
	}

	// Persist validators
	err = vm.storage.SaveValidators(vm.getValidatorsList())
	if err != nil {
		return fmt.Errorf("failed to save validators: %w", err)
	}

	return nil
}

// updateValidatorSets updates the active and inactive validator sets
func (vm *ValidatorManagerImpl) updateValidatorSets() error {
	// Clear the active and inactive sets
	vm.activeSet = make([]*types.Validator, 0, vm.config.ActiveValidatorsCount)
	vm.inactiveSet = make([]*types.Validator, 0)

	// Get all non-jailed validators
	eligibleValidators := make([]*types.Validator, 0)
	for _, v := range vm.validators {
		if v.Status != types.ValidatorStatusJailed && v.Status != types.ValidatorStatusTombstoned {
			// Update total stake from self stake and delegated stake
			v.TotalStake = v.SelfStake

			// Try to get delegated stake from stake manager
			delegatedStake, err := vm.stakeManager.GetDelegatedStake(v.PublicKey)
			if err == nil {
				v.TotalStake += delegatedStake
			}

			// Update voting power based on total stake
			v.VotingPower = v.TotalStake

			eligibleValidators = append(eligibleValidators, v)
		}
	}

	// Sort by stake (descending)
	sort.Slice(eligibleValidators, func(i, j int) bool {
		return eligibleValidators[i].TotalStake > eligibleValidators[j].TotalStake
	})

	// Select top validators as active
	for i, v := range eligibleValidators {
		if i < vm.config.ActiveValidatorsCount && v.SelfStake >= vm.config.MinStake {
			v.Status = types.ValidatorStatusActive
			vm.activeSet = append(vm.activeSet, v)
		} else {
			v.Status = types.ValidatorStatusInactive
			vm.inactiveSet = append(vm.inactiveSet, v)
		}
	}

	return nil
}

// getValidatorsList returns a list of all validators
func (vm *ValidatorManagerImpl) getValidatorsList() []*types.Validator {
	validators := make([]*types.Validator, 0, len(vm.validators))
	for _, v := range vm.validators {
		validators = append(validators, v)
	}
	return validators
}

// logActiveValidators logs the current active validator set
func (vm *ValidatorManagerImpl) logActiveValidators() {
	if len(vm.activeSet) == 0 {
		vm.logger.Info("No active validators")
		return
	}

	vm.logger.Info("Active validators", "count", len(vm.activeSet))
	for i, v := range vm.activeSet {
		vm.logger.Info(fmt.Sprintf("  Validator #%d", i+1),
			"publicKey", BytesToString(v.PublicKey),
			"stake", v.TotalStake,
			"votingPower", v.VotingPower)
	}
}

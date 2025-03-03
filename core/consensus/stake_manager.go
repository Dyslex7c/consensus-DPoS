// core/consensus/stake_manager.go
package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// StakeManagerConfig holds configuration for the stake manager
type StakeManagerConfig struct {
	MinStakeAmount        uint64
	UnbondingPeriod       time.Duration
	RewardPerBlock        uint64
	RewardDistribution    float64 // Percentage of rewards that go to delegators (0.0-1.0)
	MaxDelegationsPerUser int
}

// DefaultStakeManagerConfig returns the default configuration
func DefaultStakeManagerConfig() *StakeManagerConfig {
	return &StakeManagerConfig{
		MinStakeAmount:        100,
		UnbondingPeriod:       14 * 24 * time.Hour, // 14 days
		RewardPerBlock:        50,
		RewardDistribution:    0.8, // 80% to delegators, 20% to validators
		MaxDelegationsPerUser: 16,
	}
}

// StakeManagerImpl implements the StakeManager interface
type StakeManagerImpl struct {
	config            *StakeManagerConfig
	delegations       map[string][]*types.Stake // delegator -> stakes
	validatorStakes   map[string][]*types.Stake // validator -> stakes
	stakesByValidator map[string][]types.Stake
	unbondingRequests []*types.UnbondingRequest
	storage           StakeStorage
	mutex             sync.RWMutex
	logger            *utils.Logger
}

// StakeStorage interface for persistence
type StakeStorage interface {
	SaveDelegations(map[string][]*types.Stake) error
	LoadDelegations() (map[string][]*types.Stake, error)
	SaveUnbondingRequests([]*types.UnbondingRequest) error
	LoadUnbondingRequests() ([]*types.UnbondingRequest, error)
}

// NewStakeManager creates a new stake manager
func NewStakeManager(
	config *StakeManagerConfig,
	storage StakeStorage,
	logger *utils.Logger,
) *StakeManagerImpl {
	if config == nil {
		config = DefaultStakeManagerConfig()
	}

	return &StakeManagerImpl{
		config:            config,
		delegations:       make(map[string][]*types.Stake),
		validatorStakes:   make(map[string][]*types.Stake),
		unbondingRequests: make([]*types.UnbondingRequest, 0),
		storage:           storage,
		logger:            logger,
	}
}

// Initialize loads stakes from storage
func (sm *StakeManagerImpl) Initialize() error {
	// Load delegations
	delegations, err := sm.storage.LoadDelegations()
	if err != nil {
		return fmt.Errorf("failed to load delegations: %w", err)
	}

	// Load unbonding requests
	unbondingRequests, err := sm.storage.LoadUnbondingRequests()
	if err != nil {
		return fmt.Errorf("failed to load unbonding requests: %w", err)
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.delegations = delegations
	sm.unbondingRequests = unbondingRequests

	// Build validator stakes map
	sm.rebuildValidatorStakesMap()

	return nil
}

// BytesToString is a helper function to convert byte slices to string keys
func BytesToString(b []byte) string {
	return string(b)
}

// Delegate delegates stake to a validator
func (sm *StakeManagerImpl) Delegate(delegator []byte, validator []byte, amount uint64) error {
	if amount < sm.config.MinStakeAmount {
		return fmt.Errorf("stake amount %d is below minimum requirement %d",
			amount, sm.config.MinStakeAmount)
	}

	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	delegatorKey := BytesToString(delegator)
	validatorKey := BytesToString(validator)

	// Check if this delegation already exists and update it if so
	delegatorStakes := sm.delegations[delegatorKey]
	for _, stake := range delegatorStakes {
		if stake.Validator != nil && BytesToString(stake.Validator) == validatorKey {
			sm.logger.Info("Increasing existing delegation",
				"delegator", delegatorKey,
				"validator", validatorKey,
				"oldAmount", stake.Amount,
				"addAmount", amount)

			stake.Amount += amount
			stake.UpdatedAt = time.Now()

			return sm.saveDelegations()
		}
	}

	// Check for delegation limit
	if len(delegatorStakes) >= sm.config.MaxDelegationsPerUser {
		return fmt.Errorf("maximum number of delegations reached for this delegator")
	}

	// Create new delegation
	stake := &types.Stake{
		Delegator:      delegator,
		Validator:      validator,
		Amount:         amount,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		PendingRewards: 0,
		Unbonding:      false,
	}

	sm.logger.Info("New delegation created",
		"delegator", delegatorKey,
		"validator", validatorKey,
		"amount", amount)

	// Add to delegator's stakes
	sm.delegations[delegatorKey] = append(sm.delegations[delegatorKey], stake)

	// Add to validator's stakes
	sm.validatorStakes[validatorKey] = append(sm.validatorStakes[validatorKey], stake)

	return sm.saveDelegations()
}

// UnbondingRequest represents a request to undelegate tokens
type UnbondingRequest struct {
	DelegatorKey   string
	ValidatorKey   string
	Amount         uint64
	CompletionTime int64
	CreatedAt      int64
}

// Undelegate begins the unbonding process for a delegation
func (sm *StakeManagerImpl) Undelegate(delegator []byte, validator []byte, amount uint64) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	delegatorKey := BytesToString(delegator)
	validatorKey := BytesToString(validator)

	// Find the stake
	var stake *types.Stake
	delegatorStakes := sm.delegations[delegatorKey]
	// stakeIndex := -1

	for _, s := range delegatorStakes {
		if s.Validator != nil && BytesToString(s.Validator) == validatorKey {
			stake = s
			// stakeIndex = i
			break
		}
	}

	if stake == nil {
		return fmt.Errorf("delegation not found")
	}

	// Check if amount is valid
	if amount > stake.Amount {
		return fmt.Errorf("unbonding amount %d exceeds staked amount %d", amount, stake.Amount)
	}

	sm.logger.Info("Processing unbonding request",
		"delegator", delegatorKey,
		"validator", validatorKey,
		"amount", amount,
		"currentStake", stake.Amount)

	// Set unbonding flags
	completionTime := time.Now().Add(sm.config.UnbondingPeriod)

	// Create unbonding request
	unbondingRequest := &types.UnbondingRequest{
		DelegatorKey:   delegatorKey,
		ValidatorKey:   validatorKey,
		Amount:         amount,
		CompletionTime: completionTime.Unix(),
		CreatedAt:      time.Now().Unix(),
	}

	// Add to unbonding requests
	sm.unbondingRequests = append(sm.unbondingRequests, unbondingRequest)

	// Update or remove the stake
	if amount == stake.Amount {
		// Set as unbonding
		stake.Unbonding = true
		stake.UnbondingCompleteAt = completionTime

		// Remove the stake completely when unbonding completes
		// For now, just mark it as unbonding
		stake.UpdatedAt = time.Now()
	} else {
		// Reduce the stake amount
		stake.Amount -= amount
		stake.UpdatedAt = time.Now()

		// Create a new stake entry for the unbonding amount
		unbondingStake := &types.Stake{
			Delegator:           delegator,
			Validator:           validator,
			Amount:              amount,
			CreatedAt:           stake.CreatedAt,
			UpdatedAt:           time.Now(),
			PendingRewards:      0,
			Unbonding:           true,
			UnbondingCompleteAt: completionTime,
		}

		sm.delegations[delegatorKey] = append(sm.delegations[delegatorKey], unbondingStake)
	}

	// Save changes
	if err := sm.saveDelegations(); err != nil {
		return err
	}

	return sm.saveUnbondingRequests()
}

// GetDelegations returns all delegations for a delegator
func (sm *StakeManagerImpl) GetDelegations(delegator []byte) ([]*types.Stake, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	delegatorKey := BytesToString(delegator)
	stakes := sm.delegations[delegatorKey]

	// Return a copy to prevent modification
	result := make([]*types.Stake, len(stakes))
	copy(result, stakes)

	return result, nil
}

// GetValidatorDelegations returns all delegations to a validator
func (sm *StakeManagerImpl) GetValidatorDelegations(validator []byte) ([]*types.Stake, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	validatorKey := BytesToString(validator)
	stakes := sm.validatorStakes[validatorKey]

	// Return a copy to prevent modification
	result := make([]*types.Stake, len(stakes))
	copy(result, stakes)

	return result, nil
}

// GetValidatorTotalStake returns the total stake for a validator
func (sm *StakeManagerImpl) GetValidatorTotalStake(validator []byte) (uint64, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	validatorKey := BytesToString(validator)
	stakes := sm.validatorStakes[validatorKey]

	var total uint64
	for _, stake := range stakes {
		if !stake.Unbonding {
			total += stake.Amount
		}
	}

	return total, nil
}

// ProcessRewards distributes rewards to validators and delegators
func (sm *StakeManagerImpl) ProcessRewards(block *types.Block) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	totalReward := sm.config.RewardPerBlock
	if totalReward == 0 {
		return nil // No rewards to distribute
	}

	// Get the block proposer
	proposer := block.Header.Proposer
	proposerKey := BytesToString(proposer)

	sm.logger.Info("Processing rewards",
		"blockHeight", block.Header.Height,
		"proposer", proposerKey,
		"totalReward", totalReward)

	// Distribute rewards to the proposer first
	proposerReward := totalReward / 20 // 5% to the proposer

	// Allocate remaining rewards to all active validators based on stake
	remainingReward := totalReward - proposerReward

	// Get all validators and their total stakes
	validatorTotalStakes := make(map[string]uint64)
	var totalSystemStake uint64

	for validatorKey, stakes := range sm.validatorStakes {
		var validatorStake uint64
		for _, stake := range stakes {
			if !stake.Unbonding {
				validatorStake += stake.Amount
			}
		}
		validatorTotalStakes[validatorKey] = validatorStake
		totalSystemStake += validatorStake
	}

	if totalSystemStake == 0 {
		sm.logger.Warn("No stake in the system, cannot distribute rewards")
		return nil
	}

	// Distribute rewards proportionally to stake
	for validatorKey, validatorStake := range validatorTotalStakes {
		// Calculate the validator's share of the total reward pool
		validatorRewardShare := uint64(float64(remainingReward) * float64(validatorStake) / float64(totalSystemStake))

		// Add proposer bonus if this is the proposer
		if validatorKey == proposerKey {
			validatorRewardShare += proposerReward
		}

		// Skip if no reward
		if validatorRewardShare == 0 {
			continue
		}

		sm.logger.Info("Distributing rewards to validator",
			"validator", validatorKey,
			"stake", validatorStake,
			"reward", validatorRewardShare)

		// Split between validator and delegators
		validatorDirectReward := uint64(float64(validatorRewardShare) * (1.0 - sm.config.RewardDistribution))
		delegatorsReward := validatorRewardShare - validatorDirectReward

		// Process delegator rewards
		stakes := sm.validatorStakes[validatorKey]
		for _, stake := range stakes {
			if stake.Unbonding {
				continue
			}

			stakeRatio := float64(stake.Amount) / float64(validatorStake)
			stakeReward := uint64(float64(delegatorsReward) * stakeRatio)

			if stakeReward > 0 {
				// Add rewards directly to the stake
				stake.Amount += stakeReward
				stake.PendingRewards += stakeReward
				stake.UpdatedAt = time.Now()

				sm.logger.Info("Rewarded delegator",
					"delegator", BytesToString(stake.Delegator),
					"validator", validatorKey,
					"reward", stakeReward,
					"newStake", stake.Amount)
			}
		}
	}

	// Save updated delegations
	return sm.saveDelegations()
}

// CompleteUnbonding finalizes unbonding for mature undelegations
func (sm *StakeManagerImpl) CompleteUnbonding() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now().Unix()

	// Find mature unbonding requests
	var pendingRequests []*types.UnbondingRequest
	var completedRequests []*types.UnbondingRequest

	for _, req := range sm.unbondingRequests {
		if req.CompletionTime <= now {
			completedRequests = append(completedRequests, req)
		} else {
			pendingRequests = append(pendingRequests, req)
		}
	}

	if len(completedRequests) == 0 {
		return nil // No mature requests
	}

	// Log the completion
	sm.logger.Info("Completing unbonding requests", "count", len(completedRequests))

	// Process the completed unbonding requests
	for _, req := range completedRequests {
		sm.logger.Info("Unbonding completed",
			"delegator", req.DelegatorKey,
			"validator", req.ValidatorKey,
			"amount", req.Amount)

		// Remove or update stakes that are unbonding
		if delegatorStakes, ok := sm.delegations[req.DelegatorKey]; ok {
			for i := 0; i < len(delegatorStakes); i++ {
				stake := delegatorStakes[i]
				validatorKey := BytesToString(stake.Validator)

				if validatorKey == req.ValidatorKey && stake.Unbonding {
					// Check if this is the completed unbonding stake
					if stake.UnbondingCompleteAt.Unix() <= now {
						// Remove this stake
						delegatorStakes = append(delegatorStakes[:i], delegatorStakes[i+1:]...)
						i-- // Adjust index as we've removed an element
					}
				}
			}

			// Update or remove delegator entry
			if len(delegatorStakes) == 0 {
				delete(sm.delegations, req.DelegatorKey)
			} else {
				sm.delegations[req.DelegatorKey] = delegatorStakes
			}
		}

		// Here you would transfer the tokens back to the delegator
		// This would typically involve a state update
		// For this example, we're just completing the unbonding
	}

	// Update the list of pending requests
	sm.unbondingRequests = pendingRequests

	// Rebuild validator stakes map
	sm.rebuildValidatorStakesMap()

	// Save the updated unbonding requests
	return sm.saveUnbondingRequests()
}

// rebuildValidatorStakesMap rebuilds the map of validator stakes
func (sm *StakeManagerImpl) rebuildValidatorStakesMap() {
	sm.validatorStakes = make(map[string][]*types.Stake)

	for _, delegatorStakes := range sm.delegations {
		for _, stake := range delegatorStakes {
			validatorKey := BytesToString(stake.Validator)
			sm.validatorStakes[validatorKey] = append(
				sm.validatorStakes[validatorKey], stake)
		}
	}
}

// saveDelegations persists delegations to storage
func (sm *StakeManagerImpl) saveDelegations() error {
	return sm.storage.SaveDelegations(sm.delegations)
}

// saveUnbondingRequests persists unbonding requests to storage
func (sm *StakeManagerImpl) saveUnbondingRequests() error {
	return sm.storage.SaveUnbondingRequests(sm.unbondingRequests)
}

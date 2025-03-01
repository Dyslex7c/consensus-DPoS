// Package consensus contains the interfaces and implementations for the DPoS consensus engine
package consensus

import (
	"context"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
)

// Engine defines the interface for the consensus engine
type Engine interface {
	// Start starts the consensus engine
	Start(ctx context.Context) error

	// Stop stops the consensus engine
	Stop() error

	// IsRunning returns whether the consensus engine is running
	IsRunning() bool

	// ProposeBlock creates and proposes a new block
	ProposeBlock(ctx context.Context) (*types.Block, error)

	// ValidateBlock validates a proposed block
	ValidateBlock(block *types.Block) error

	// FinalizeBlock finalizes a block after sufficient validation
	FinalizeBlock(block *types.Block) error

	// ProcessTransaction processes a new transaction
	ProcessTransaction(tx *types.Transaction) error
}

// ValidatorManager defines the interface for managing validators
type ValidatorManager interface {
	// GetValidators returns the current set of validators
	GetValidators() ([]*types.Validator, error)

	// GetActiveValidators returns the active validator set for the current epoch
	GetActiveValidators() ([]*types.Validator, error)

	// IsValidator checks if a public key belongs to a validator
	IsValidator(publicKey []byte) (bool, error)

	// RegisterValidator registers a new validator
	RegisterValidator(validator *types.Validator) error

	// UpdateValidator updates an existing validator
	UpdateValidator(validator *types.Validator) error

	// RemoveValidator removes a validator
	RemoveValidator(publicKey []byte) error

	// RotateValidators performs the validator rotation at epoch boundaries
	RotateValidators(epoch uint64) error

	// SlashValidator applies slashing penalties to a validator
	SlashValidator(publicKey []byte, reason string, amount uint64) error

	// JailValidator jails a validator for a specified duration
	JailValidator(publicKey []byte, duration uint64) error

	// UnjailValidator releases a validator from jail
	UnjailValidator(publicKey []byte) error
}

// StakeManager defines the interface for managing stakes and delegations
type StakeManager interface {
	// Delegate delegates stake to a validator
	Delegate(delegator []byte, validator []byte, amount uint64) error

	// Undelegate begins the unbonding process for a delegation
	Undelegate(delegator []byte, validator []byte, amount uint64) error

	// GetDelegations returns all delegations for a delegator
	GetDelegations(delegator []byte) ([]*types.Stake, error)

	// GetValidatorDelegations returns all delegations to a validator
	GetValidatorDelegations(validator []byte) ([]*types.Stake, error)

	// ProcessRewards distributes rewards to validators and delegators
	ProcessRewards(block *types.Block) error

	// CompleteUnbonding finalizes unbonding for mature undelegations
	CompleteUnbonding() error
}

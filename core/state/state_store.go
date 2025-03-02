// Package state provides state management functionality for the blockchain
package state

import (
	"github.com/Dyslex7c/consensus-DPoS/core/types"
)

// StateStore defines the interface for state storage and retrieval
type StateStore interface {
	// Account methods
	GetBalance(address []byte) (uint64, error)
	SetBalance(address []byte, amount uint64) error
	TransferBalance(from, to []byte, amount uint64) error

	// Validator methods
	GetValidators() ([]*types.Validator, error)
	GetValidator(address []byte) (*types.Validator, error)
	AddValidator(validator *types.Validator) error
	UpdateValidator(validator *types.Validator) error
	RemoveValidator(address []byte) error

	// Stake methods
	GetTotalStake() (uint64, error)
	GetStake(delegator, validator []byte) (*types.Stake, error)
	AddStake(stake *types.Stake) error
	UpdateStake(stake *types.Stake) error
	RemoveStake(delegator, validator []byte) error
	GetValidatorTotalStake(validator []byte) (uint64, error)
	GetDelegatorStakes(delegator []byte) ([]*types.Stake, error)

	// Block state methods
	GetLatestBlockHeight() (uint64, error)
	SetLatestBlockHeight(height uint64) error
	GetLatestBlockHash() ([]byte, error)
	SetLatestBlockHash(hash []byte) error

	// Transaction methods
	GetProcessedTransaction(txID []byte) (bool, error)
	MarkTransactionProcessed(txID []byte) error

	// State operation methods
	Commit() error
	Rollback() error
	Reset() error

	// For snapshots/forks
	Clone() (StateStore, error)
}

// StateTransition represents a transition in the blockchain state
type StateTransition struct {
	// Pre-state root hash
	PreStateRoot []byte
	// Post-state root hash
	PostStateRoot []byte
	// Block that caused this transition
	BlockHeader *types.BlockHeader
	// Transactions applied in this transition
	Transactions []*types.Transaction
}

// ApplyBlock applies a block to the state and returns the state transition
type BlockProcessor interface {
	ApplyBlock(block *types.Block, state StateStore) (*StateTransition, error)
}

// ApplyTransaction applies a transaction to the state
type TransactionProcessor interface {
	ApplyTransaction(tx *types.Transaction, state StateStore) error
}

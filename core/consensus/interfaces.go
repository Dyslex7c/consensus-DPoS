package consensus

import (
	"github.com/Dyslex7c/consensus-DPoS/core/types"
)

// ValidatorManager defines the interface for managing validators
type ValidatorManager interface {
	// GetActiveValidators returns the current active validator set
	GetActiveValidators() ([]types.Validator, error)
	// IsValidator checks if the given public key belongs to a validator
	IsValidator(publicKey []byte) (bool, error)
	// RotateValidators updates the validator set for a new epoch
	RotateValidators(epochNumber uint64) error
	// GetValidatorByPublicKey returns a validator by their public key
	GetValidatorByPublicKey(publicKey []byte) (*types.Validator, error)
	// UpdateValidator updates a validator's information
	UpdateValidator(validator *types.Validator) error
}

// StakeManager defines the interface for managing stakes
type StakeManager interface {
	// ProcessRewards distributes rewards for a block
	ProcessRewards(block *types.Block) error
	// CompleteUnbonding completes any unbonding stakes that are ready
	CompleteUnbonding() error
	// GetStakesByDelegator returns all stakes for a delegator
	GetStakesByDelegator(delegator []byte) ([]types.Stake, error)
	// GetStakesByValidator returns all stakes for a validator
	GetStakesByValidator(validator []byte) ([]types.Stake, error)
	// Delegate adds or increases a stake
	Delegate(delegator, validator []byte, amount uint64) error
	// Undelegate begins the unbonding process for a stake
	Undelegate(delegator, validator []byte, amount uint64) error
}

// TxPool defines the interface for the transaction pool
type TxPool interface {
	// AddTransaction adds a transaction to the pool
	AddTransaction(tx *types.Transaction) error
	// RemoveTransaction removes a transaction from the pool
	RemoveTransaction(txID []byte)
	// GetPendingTransactions returns up to maxTxs transactions
	GetPendingTransactions(maxTxs int) []types.Transaction
	// GetTransaction returns a transaction by its ID
	GetTransaction(txID []byte) (*types.Transaction, error)
	// Count returns the number of transactions in the pool
	Count() int
}

// Blockchain defines the interface for blockchain operations
type Blockchain interface {
	// GetLatestBlock returns the latest block in the chain
	GetLatestBlock() (*types.Block, error)
	// GetBlockByHeight returns a block by its height
	GetBlockByHeight(height uint64) (*types.Block, error)
	// AddBlock adds a new block to the chain
	AddBlock(block *types.Block) error
	// ValidateTransaction validates a transaction
	ValidateTransaction(tx *types.Transaction) error
	// ApplyTransaction applies a transaction to the state
	ApplyTransaction(tx *types.Transaction) error
	// GetOurValidator returns this node's validator information
	GetOurValidator() *types.Validator
	// SignBlock signs a block header
	SignBlock(header *types.BlockHeader) ([]byte, error)
	// VerifyBlockSignature verifies a block's signature
	VerifyBlockSignature(block *types.Block) bool
	// VerifySignature verifies a signature against data
	VerifySignature(publicKey, data, signature []byte) bool
	// CalculateStateRoot calculates a new state root after applying transactions
	CalculateStateRoot(txs []types.Transaction) ([]byte, error)
}

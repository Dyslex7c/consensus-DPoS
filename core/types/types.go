package types

import (
	"time"

	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// Block represents a single block in the blockchain
type Block struct {
	// Block header
	Header BlockHeader
	// List of transactions included in this block
	Transactions []Transaction
	// Validator signature who proposed this block
	ProposerSignature []byte
	// Signatures from validators who confirmed this block
	ValidatorSignatures []ValidatorSignature
}

// CalculateHash calculates and returns the hash of the block
// This is used for block verification and as the PreviousHash in the next block
func (b *Block) CalculateHash() []byte {
	// Create a slice to hold all data to be hashed
	var data []byte

	// Add header fields to the data
	// Convert uint64 to bytes
	heightBytes := make([]byte, 8)
	utils.PutUint64(heightBytes, b.Header.Height)
	data = append(data, heightBytes...)

	// Add previous hash
	data = append(data, b.Header.PreviousHash...)

	// Add timestamp as bytes
	timeBytes := []byte(b.Header.Timestamp.String())
	data = append(data, timeBytes...)

	// Add transactions root
	data = append(data, b.Header.TransactionsRoot...)

	// Add state root
	data = append(data, b.Header.StateRoot...)

	// Add proposer
	data = append(data, b.Header.Proposer...)

	// Add epoch
	epochBytes := make([]byte, 8)
	utils.PutUint64(epochBytes, b.Header.Epoch)
	data = append(data, epochBytes...)

	// Add transaction IDs to maintain deterministic hashing
	// without including entire transactions for efficiency
	for _, tx := range b.Transactions {
		data = append(data, tx.ID...)
	}

	// Add proposer signature
	data = append(data, b.ProposerSignature...)

	// We don't include validator signatures in the hash calculation
	// as they are collected after the block is proposed

	// Calculate the final hash using the utils.Hash function
	return utils.Hash(data)
}

// BlockHeader contains metadata about a block
type BlockHeader struct {
	// Height of the block in the chain
	Height uint64
	// Hash of the previous block
	PreviousHash []byte
	// Time when the block was created
	Timestamp time.Time
	// Merkle root of transactions
	TransactionsRoot []byte
	// Merkle root of the state after applying this block
	StateRoot []byte
	// Proposer of this block (validator public key)
	Proposer []byte
	// Current epoch number
	Epoch uint64
}

// Transaction represents a single transaction in the blockchain
type Transaction struct {
	// Transaction ID/hash
	ID []byte
	// Sender's public key
	Sender []byte
	// Recipient's address/public key
	Recipient []byte
	// Amount being transferred
	Amount uint64
	// Transaction type (transfer, delegate, undelegate, etc.)
	Type TransactionType
	// Additional data specific to transaction type
	Data []byte
	// Signature of the transaction data
	Signature []byte
	// Transaction Nonce
	Nonce uint64
	// Transaction timestamp
	Timestamp time.Time
}

// TransactionType defines the type of transaction
type TransactionType uint8

const (
	// TransactionTypeTransfer represents a standard token transfer
	TransactionTypeTransfer TransactionType = iota
	// TransactionTypeDelegate represents a delegation of stake to a validator
	TransactionTypeDelegate
	// TransactionTypeUndelegate represents an undelegation of stake
	TransactionTypeUndelegate
	// TransactionTypeRegisterValidator represents a validator registration
	TransactionTypeRegisterValidator
	// TransactionTypeUnregisterValidator represents a validator unregistration
	TransactionTypeUnregisterValidator
)

// Validator represents a node that participates in consensus
type Validator struct {
	// Validator's address (usually derived from public key)
	Address []byte
	// Validator's public key
	PublicKey []byte
	// Validator's voting power (proportional to stake)
	VotingPower uint64
	// Total stake delegated to this validator
	TotalStake uint64
	// Validator's own stake
	SelfStake uint64
	// Commission rate (percentage of rewards kept by validator)
	Commission uint8
	// When the validator joined
	JoinedAt time.Time
	// Validator status
	Status ValidatorStatus
	// Uptime percentage
	Uptime float64
	// Number of blocks proposed
	BlocksProposed uint64
	// Number of blocks validated
	BlocksValidated uint64
	// Jailed until timestamp (zero if not jailed)
	JailedUntil time.Time
	// Missed blocks in a row (for slashing)
	MissedBlocksCounter uint32
}

// ValidatorStatus represents the current status of a validator
type ValidatorStatus uint8

const (
	// ValidatorStatusActive means the validator is active and participating
	ValidatorStatusActive ValidatorStatus = iota
	// ValidatorStatusInactive means the validator is registered but not in the active set
	ValidatorStatusInactive
	// ValidatorStatusJailed means the validator has been jailed for misbehavior
	ValidatorStatusJailed
	// ValidatorStatusTombstoned means the validator has been permanently removed
	ValidatorStatusTombstoned
)

// Stake represents a delegation of tokens to a validator
type Stake struct {
	// Delegator's public key
	Delegator []byte
	// Validator's public key
	Validator []byte
	// Amount staked
	Amount uint64
	// When the delegation was made
	CreatedAt time.Time
	// When the delegation was last updated
	UpdatedAt time.Time
	// Pending rewards
	PendingRewards uint64
	// Is this stake in unbonding period
	Unbonding bool
	// When the unbonding period ends (if Unbonding is true)
	UnbondingCompleteAt time.Time
}

// UnbondingRequest represents a request to undelegate tokens
type UnbondingRequest struct {
	// Delegator's address as string key (derived from public key)
	DelegatorKey string
	// Validator's address as string key (derived from public key)
	ValidatorKey string
	// Amount to undelegate
	Amount uint64
	// Unix timestamp when the unbonding will be completed
	CompletionTime int64
	// Unix timestamp when the unbonding request was created
	CreatedAt int64
}

// ValidatorSignature represents a validator's signature on a block
type ValidatorSignature struct {
	// Validator's public key
	ValidatorPublicKey []byte
	// Signature data
	Signature []byte
	// When the signature was made
	Timestamp time.Time
}

// ConsensusParams defines the parameters for the consensus mechanism
type ConsensusParams struct {
	// Number of blocks in an epoch
	EpochLength uint64
	// Number of validators in the active set
	ActiveValidators uint32
	// Minimum stake required to become a validator
	MinimumStake uint64
	// Unbonding period in seconds
	UnbondingPeriod uint64
	// Block time target in seconds
	BlockTimeTarget uint32
	// Maximum blocks a validator can miss before being jailed
	MaxMissedBlocks uint32
	// Percentage of stake slashed for double signing (basis points)
	DoubleSignSlashRate uint16
	// Percentage of stake slashed for downtime (basis points)
	DowntimeSlashRate uint16
	// Jail duration for downtime in seconds
	DowntimeJailDuration uint64
}

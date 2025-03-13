package consensus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/utils"
)

// Config holds the configuration for the DPoS engine
type DPoSConfig struct {
	// Time between blocks in seconds
	BlockInterval time.Duration
	// Number of validators in the active set
	ActiveValidators int
	// Duration of an epoch in blocks
	EpochLength uint64
	// Minimum stake required to become a validator
	MinValidatorStake uint64
	// Maximum number of transactions per block
	MaxTxPerBlock int
	// Unbonding period in seconds
	UnbondingPeriod uint64
	// Maximum blocks a validator can miss before being jailed
	MaxMissedBlocks uint32
	// Percentage of stake slashed for double signing (basis points)
	DoubleSignSlashRate uint16
	// Percentage of stake slashed for downtime (basis points)
	DowntimeSlashRate uint16
	// Jail duration for downtime in seconds
	DowntimeJailDuration uint64
}

// DefaultConfig returns the default DPoS configuration
func DefaultConfig() *DPoSConfig {
	return &DPoSConfig{
		BlockInterval:        3 * time.Second,
		ActiveValidators:     21,
		EpochLength:          100,
		MinValidatorStake:    1000,
		MaxTxPerBlock:        500,
		UnbondingPeriod:      60 * 60 * 24 * 7, // 7 days in seconds
		MaxMissedBlocks:      10,
		DoubleSignSlashRate:  1000,         // 10% in basis points
		DowntimeSlashRate:    100,          // 1% in basis points
		DowntimeJailDuration: 60 * 60 * 24, // 24 hours in seconds
	}
}

func ConvertConsensusParams(params *types.ConsensusParams) *DPoSConfig {
	return &DPoSConfig{
		BlockInterval:        time.Duration(params.BlockTimeTarget) * time.Second,
		ActiveValidators:     int(params.ActiveValidators),
		EpochLength:          params.EpochLength,
		MinValidatorStake:    params.MinimumStake, // Notice the name difference
		MaxTxPerBlock:        500,                 // Default value as it's missing in ConsensusParams
		UnbondingPeriod:      params.UnbondingPeriod,
		MaxMissedBlocks:      params.MaxMissedBlocks,
		DoubleSignSlashRate:  params.DoubleSignSlashRate,
		DowntimeSlashRate:    params.DowntimeSlashRate,
		DowntimeJailDuration: params.DowntimeJailDuration,
	}
}

// DPoSEngine implements the DPoS consensus algorithm
type DPoSEngine struct {
	config        *DPoSConfig
	validatorMgr  ValidatorManager
	stakeMgr      StakeManager
	txPool        TxPool
	blockchain    Blockchain
	currentHeight uint64
	currentEpoch  uint64
	mutex         sync.RWMutex
	isRunning     bool
	stopChan      chan struct{}
	logger        *utils.Logger
}

// NewDPoSEngine creates a new DPoS engine instance
func NewDPoSEngine(
	config *DPoSConfig,
	validatorMgr ValidatorManager,
	stakeMgr StakeManager,
	txPool TxPool,
	blockchain Blockchain,
	logger *utils.Logger,
) *DPoSEngine {
	if config == nil {
		config = DefaultConfig()
	}

	return &DPoSEngine{
		config:        config,
		validatorMgr:  validatorMgr,
		stakeMgr:      stakeMgr,
		txPool:        txPool,
		blockchain:    blockchain,
		currentEpoch:  0,
		currentHeight: 0,
		isRunning:     false,
		stopChan:      make(chan struct{}),
		logger:        logger,
	}
}

// Start starts the consensus engine
func (e *DPoSEngine) Start(ctx context.Context) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.isRunning {
		return fmt.Errorf("consensus engine is already running")
	}

	e.logger.Info("Starting DPoS consensus engine")
	e.isRunning = true

	// Start the main consensus loop
	go e.consensusLoop(ctx)

	return nil
}

// Stop stops the consensus engine
func (e *DPoSEngine) Stop() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if !e.isRunning {
		return fmt.Errorf("consensus engine is not running")
	}

	e.logger.Info("Stopping DPoS consensus engine")
	close(e.stopChan)
	e.isRunning = false

	return nil
}

// IsRunning returns whether the consensus engine is running
func (e *DPoSEngine) IsRunning() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.isRunning
}

// consensusLoop is the main loop for block production
func (e *DPoSEngine) consensusLoop(ctx context.Context) {
	ticker := time.NewTicker(e.config.BlockInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if it's our turn to propose a block
			if e.isMyTurn() {
				e.logger.Info("It's our turn to propose a block")

				// Propose a new block
				block, err := e.ProposeBlock(ctx)
				if err != nil {
					e.logger.Error("Failed to propose block", "error", err)
					continue
				}

				// Finalize and broadcast the block
				err = e.FinalizeBlock(block)
				if err != nil {
					e.logger.Error("Failed to finalize block", "error", err)
					continue
				}

				e.logger.Info("Successfully proposed and finalized block", "height", block.Header.Height)
			}
		case <-ctx.Done():
			e.logger.Info("Consensus loop terminated due to context cancellation")
			return
		case <-e.stopChan:
			e.logger.Info("Consensus loop terminated due to stop signal")
			return
		}
	}
}

// isMyTurn determines if it's the current node's turn to propose a block
func (e *DPoSEngine) isMyTurn() bool {
	validators, err := e.validatorMgr.GetActiveValidators()
	if err != nil {
		e.logger.Error("Failed to get active validators", "error", err)
		return false
	}

	if len(validators) == 0 {
		e.logger.Error("No active validators found")
		return false
	}

	// Get the current timestamp
	now := time.Now().Unix()

	// Calculate the expected block slot
	slot := (now / int64(e.config.BlockInterval.Seconds())) % int64(len(validators))

	// Get our validator info
	ourValidator := e.blockchain.GetOurValidator()
	if ourValidator == nil {
		return false
	}

	// Check if we're the validator for this slot
	// Compare public keys instead of IDs to match the types.go structure
	return string(validators[slot].PublicKey) == string(ourValidator.PublicKey)
}

// ProposeBlock creates and proposes a new block
func (e *DPoSEngine) ProposeBlock(ctx context.Context) (*types.Block, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Get the latest block
	latestBlock, err := e.blockchain.GetLatestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Get pending transactions from the pool
	pendingTxs := e.txPool.GetPendingTransactions(e.config.MaxTxPerBlock)

	// Get our validator
	ourValidator := e.blockchain.GetOurValidator()
	if ourValidator == nil {
		return nil, fmt.Errorf("failed to get our validator information")
	}

	// Create the new block
	block := &types.Block{
		Header: types.BlockHeader{
			Height:           latestBlock.Header.Height + 1,
			PreviousHash:     latestBlock.CalculateHash(),
			Timestamp:        time.Now(),
			TransactionsRoot: calculateMerkleRoot(pendingTxs),
			StateRoot:        []byte{}, // Will be populated later
			Proposer:         ourValidator.PublicKey,
			Epoch:            latestBlock.Header.Height/e.config.EpochLength + 1,
		},
		Transactions:        pendingTxs,
		ProposerSignature:   []byte{}, // Will be populated later
		ValidatorSignatures: []types.ValidatorSignature{},
	}

	// Calculate transaction merkle root
	block.Header.TransactionsRoot = calculateMerkleRoot(pendingTxs)

	// Update state and get state root
	stateRoot, err := e.blockchain.CalculateStateRoot(pendingTxs)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate state root: %w", err)
	}
	block.Header.StateRoot = stateRoot

	// Sign the block
	signature, err := e.blockchain.SignBlock(&block.Header)
	if err != nil {
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}
	block.ProposerSignature = signature

	// Add our validator signature
	validatorSig := types.ValidatorSignature{
		ValidatorPublicKey: ourValidator.PublicKey,
		Signature:          signature,
		Timestamp:          time.Now(),
	}
	block.ValidatorSignatures = append(block.ValidatorSignatures, validatorSig)

	e.logger.Info("Block proposed", "height", block.Header.Height, "txs", len(pendingTxs))

	return block, nil
}

// ValidateBlock validates a proposed block
func (e *DPoSEngine) ValidateBlock(block *types.Block) error {
	// Verify the block height
	latestBlock, err := e.blockchain.GetLatestBlock()
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	if block.Header.Height != latestBlock.Header.Height+1 {
		return fmt.Errorf("invalid block height: expected %d, got %d", latestBlock.Header.Height+1, block.Header.Height)
	}

	// Verify the previous hash
	if string(block.Header.PreviousHash) != string(latestBlock.CalculateHash()) {
		return fmt.Errorf("invalid previous hash")
	}

	// Verify the block timestamp
	if block.Header.Timestamp.Before(latestBlock.Header.Timestamp) {
		return fmt.Errorf("block timestamp must be greater than previous block")
	}

	// Verify block proposer is a valid validator
	isValidator, err := e.validatorMgr.IsValidator(block.Header.Proposer)
	if err != nil {
		return fmt.Errorf("failed to verify proposer: %w", err)
	}
	if !isValidator {
		return fmt.Errorf("block proposer is not a valid validator")
	}

	// Verify it's the proposer's turn
	validators, err := e.validatorMgr.GetActiveValidators()
	if err != nil {
		return fmt.Errorf("failed to get active validators: %w", err)
	}

	if len(validators) == 0 {
		return fmt.Errorf("no active validators found")
	}

	// Calculate the expected block slot
	blockTime := block.Header.Timestamp.Unix()
	slot := (blockTime / int64(e.config.BlockInterval.Seconds())) % int64(len(validators))

	if string(validators[slot].PublicKey) != string(block.Header.Proposer) {
		return fmt.Errorf("not the proposer's turn")
	}

	// Verify the transactions root
	calculatedRoot := calculateMerkleRoot(block.Transactions)
	if string(calculatedRoot) != string(block.Header.TransactionsRoot) {
		return fmt.Errorf("invalid transactions root")
	}

	// Verify the epoch
	expectedEpoch := block.Header.Height / e.config.EpochLength
	if block.Header.Epoch != expectedEpoch {
		return fmt.Errorf("invalid epoch number")
	}

	// Verify all transactions
	for _, tx := range block.Transactions {
		if err := e.blockchain.ValidateTransaction(&tx); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	// Verify the proposer signature
	if !e.blockchain.VerifyBlockSignature(block) {
		return fmt.Errorf("invalid block signature")
	}

	// Verify validator signatures
	if err := e.verifyValidatorSignatures(block); err != nil {
		return fmt.Errorf("invalid validator signatures: %w", err)
	}

	return nil
}

// verifyValidatorSignatures verifies signatures from validators
func (e *DPoSEngine) verifyValidatorSignatures(block *types.Block) error {
	validators, err := e.validatorMgr.GetActiveValidators()
	if err != nil {
		return fmt.Errorf("failed to get active validators: %w", err)
	}

	// Create a map for easy lookup
	validatorMap := make(map[string]*types.Validator)
	for i, v := range validators {
		validatorMap[string(v.PublicKey)] = &validators[i]
	}

	// Verify each signature
	for _, sig := range block.ValidatorSignatures {
		// Check if validator is in the active set
		validator, exists := validatorMap[string(sig.ValidatorPublicKey)]
		if !exists {
			return fmt.Errorf("signature from non-active validator")
		}

		// Verify signature
		if !e.blockchain.VerifySignature(
			sig.ValidatorPublicKey,
			block.CalculateHash(),
			sig.Signature,
		) {
			return fmt.Errorf("invalid signature from validator %x", validator.Address)
		}
	}

	return nil
}

// FinalizeBlock finalizes a block after sufficient validation
func (e *DPoSEngine) FinalizeBlock(block *types.Block) error {
	// Validate the block first
	if err := e.ValidateBlock(block); err != nil {
		return fmt.Errorf("block validation failed: %w", err)
	}

	// Add the block to the blockchain
	if err := e.blockchain.AddBlock(block); err != nil {
		return fmt.Errorf("failed to add block to blockchain: %w", err)
	}

	// Remove the block's transactions from the transaction pool
	for _, tx := range block.Transactions {
		e.txPool.RemoveTransaction(tx.ID)
	}

	// Update state with the transactions
	for _, tx := range block.Transactions {
		if err := e.blockchain.ApplyTransaction(&tx); err != nil {
			e.logger.Error("Failed to apply transaction", "tx", fmt.Sprintf("%x", tx.ID), "error", err)
		}
	}

	// If this is an epoch boundary, update validators and process rewards
	if block.Header.Height%e.config.EpochLength == 0 {
		e.logger.Info("Reached epoch boundary", "epoch", block.Header.Epoch)

		// Process rewards for the previous epoch
		if err := e.stakeMgr.ProcessRewards(block); err != nil {
			e.logger.Error("Failed to process rewards", "error", err)
		}

		// Complete any pending unbonding
		if err := e.stakeMgr.CompleteUnbonding(); err != nil {
			e.logger.Error("Failed to complete unbonding", "error", err)
		}

		// Rotate validators for the new epoch
		if err := e.validatorMgr.RotateValidators(block.Header.Epoch); err != nil {
			e.logger.Error("Failed to rotate validators", "error", err)
		}
	}

	e.logger.Info("Block finalized", "height", block.Header.Height, "txs", len(block.Transactions))

	// Update current height and epoch
	e.mutex.Lock()
	e.currentHeight = block.Header.Height
	e.currentEpoch = block.Header.Epoch
	e.mutex.Unlock()

	return nil
}

// ProcessTransaction processes a new transaction
func (e *DPoSEngine) ProcessTransaction(tx *types.Transaction) error {
	// Validate the transaction
	if err := e.blockchain.ValidateTransaction(tx); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	// Add to transaction pool
	if err := e.txPool.AddTransaction(tx); err != nil {
		return fmt.Errorf("failed to add transaction to pool: %w", err)
	}

	return nil
}

// Helper function to calculate merkle root
func calculateMerkleRoot(txs []types.Transaction) []byte {
	if len(txs) == 0 {
		return []byte{}
	}

	// Simple implementation for now - in production, implement a real Merkle tree
	hashData := make([]byte, 0)
	for _, tx := range txs {
		hashData = append(hashData, tx.ID...)
	}

	return utils.Hash(hashData)
}

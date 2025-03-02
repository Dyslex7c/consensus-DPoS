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
}

// DefaultConfig returns the default DPoS configuration
func DefaultConfig() *DPoSConfig {
	return &DPoSConfig{
		BlockInterval:     3 * time.Second,
		ActiveValidators:  21,
		EpochLength:       100,
		MinValidatorStake: 1000,
		MaxTxPerBlock:     500,
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
	return validators[slot].PublicKey.Equal(ourValidator.PublicKey)
}

// ProposeBlock creates and proposes a new block
func (e *DPoSEngine) ProposeBlock(ctx context.Context) (*types.Block, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// Get the latest block height
	latestBlock, err := e.blockchain.GetLatestBlock()
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	// Get pending transactions from the pool
	pendingTxs := e.txPool.GetPendingTransactions(e.config.MaxTxPerBlock)

	// Create the new block
	block := &types.Block{
		Header: &types.BlockHeader{
			Version:          1,
			Height:           latestBlock.Header.Height + 1,
			PreviousHash:     latestBlock.Hash(),
			Timestamp:        time.Now().UnixNano(),
			ProposerID:       e.blockchain.GetOurValidator().ID,
			TransactionCount: uint32(len(pendingTxs)),
		},
		Transactions: pendingTxs,
	}

	// Calculate the epoch
	e.currentHeight = block.Header.Height
	e.currentEpoch = e.currentHeight / e.config.EpochLength

	// Check if we're at an epoch boundary
	if e.currentHeight%e.config.EpochLength == 0 {
		e.logger.Info("Reached epoch boundary", "epoch", e.currentEpoch)

		// Rotate validators for the new epoch
		err := e.validatorMgr.RotateValidators(e.currentEpoch)
		if err != nil {
			return nil, fmt.Errorf("failed to rotate validators: %w", err)
		}

		// Add epoch metadata to the block
		block.Header.EpochNumber = e.currentEpoch
		block.Header.IsEpochBoundary = true

		// Get the new active validator set and include in the block
		activeValidators, err := e.validatorMgr.GetActiveValidators()
		if err != nil {
			return nil, fmt.Errorf("failed to get active validators: %w", err)
		}

		// Store validator info in the block
		block.Validators = activeValidators
	} else {
		block.Header.EpochNumber = e.currentEpoch
		block.Header.IsEpochBoundary = false
	}

	// Calculate merkle root for transactions
	block.Header.MerkleRoot = block.CalculateMerkleRoot()

	// Sign the block
	signature, err := e.blockchain.SignBlock(block)
	if err != nil {
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}
	block.Header.Signature = signature

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
	if !block.Header.PreviousHash.Equal(latestBlock.Hash()) {
		return fmt.Errorf("invalid previous hash")
	}

	// Verify the block timestamp
	if block.Header.Timestamp <= latestBlock.Header.Timestamp {
		return fmt.Errorf("block timestamp must be greater than previous block")
	}

	// Verify block proposer is a valid validator
	isValidator, err := e.validatorMgr.IsValidator(block.Header.ProposerID)
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
	blockTime := time.Unix(0, block.Header.Timestamp)
	slot := (blockTime.Unix() / int64(e.config.BlockInterval.Seconds())) % int64(len(validators))

	if !validators[slot].PublicKey.Equal(block.Header.ProposerID) {
		return fmt.Errorf("not the proposer's turn")
	}

	// Verify the merkle root
	calculatedRoot := block.CalculateMerkleRoot()
	if !calculatedRoot.Equal(block.Header.MerkleRoot) {
		return fmt.Errorf("invalid merkle root")
	}

	// Verify the epoch boundary logic
	expectedEpoch := block.Header.Height / e.config.EpochLength
	if block.Header.EpochNumber != expectedEpoch {
		return fmt.Errorf("invalid epoch number")
	}

	if block.Header.IsEpochBoundary != (block.Header.Height%e.config.EpochLength == 0) {
		return fmt.Errorf("invalid epoch boundary flag")
	}

	// Verify all transactions
	for _, tx := range block.Transactions {
		if err := e.blockchain.ValidateTransaction(tx); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}

	// Verify the block signature
	if !e.blockchain.VerifyBlockSignature(block) {
		return fmt.Errorf("invalid block signature")
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
		e.txPool.RemoveTransaction(tx.Hash())
	}

	// Update state with the transactions
	for _, tx := range block.Transactions {
		if err := e.blockchain.ApplyTransaction(tx); err != nil {
			e.logger.Error("Failed to apply transaction", "tx", tx.Hash(), "error", err)
		}
	}

	// If this is an epoch boundary, finalize the validator rotation
	if block.Header.IsEpochBoundary {
		// Process rewards for the previous epoch
		if err := e.stakeMgr.ProcessRewards(block); err != nil {
			e.logger.Error("Failed to process rewards", "error", err)
		}

		// Complete any pending unbonding
		if err := e.stakeMgr.CompleteUnbonding(); err != nil {
			e.logger.Error("Failed to complete unbonding", "error", err)
		}
	}

	e.logger.Info("Block finalized", "height", block.Header.Height, "txs", len(block.Transactions))

	// Update current height and epoch
	e.mutex.Lock()
	e.currentHeight = block.Header.Height
	e.currentEpoch = e.currentHeight / e.config.EpochLength
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

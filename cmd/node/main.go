package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/config"
	"github.com/Dyslex7c/consensus-DPoS/core/consensus"
	"github.com/Dyslex7c/consensus-DPoS/core/state"
	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/Dyslex7c/consensus-DPoS/crypto"
	"github.com/Dyslex7c/consensus-DPoS/storage"
	"github.com/Dyslex7c/consensus-DPoS/utils"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to the configuration file")
	logDir := flag.String("logdir", "", "Directory for log files")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Convert log level string to LogLevel type
	var logLevel utils.LogLevel
	switch cfg.General.LogLevel {
	case "debug":
		logLevel = utils.DEBUG
	case "info":
		logLevel = utils.INFO
	case "warn":
		logLevel = utils.WARN
	case "error":
		logLevel = utils.ERROR
	case "fatal":
		logLevel = utils.FATAL
	default:
		logLevel = utils.INFO // Default to INFO if unrecognized
	}

	// Setup logger
	logger, err := utils.NewLogger(logLevel, *logDir)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("Starting DPoS node", "version", cfg.General.NetworkID)

	// Initialize database
	dbPath := filepath.Join(cfg.General.DataDir, "db")
	db, err := storage.NewLevelDBStore(dbPath)
	if err != nil {
		logger.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize state
	stateStore := state.NewMemoryStore(db)
	err = stateStore.Initialize()
	if err != nil {
		logger.Error("Failed to initialize state", "error", err)
		os.Exit(1)
	}

	// Load or create keys
	keyManager, err := crypto.NewKeyManager(filepath.Join(cfg.General.DataDir, "keys"))
	if err != nil {
		logger.Error("Failed to initialize key manager", "error", err)
		os.Exit(1)
	}

	// Create blockchain
	blockchain := &BlockchainImpl{
		db:         db,
		stateStore: stateStore,
		keyManager: keyManager,
		logger:     logger,
	}

	// Initialize transaction pool
	txPool := &TxPoolImpl{
		blockchain: blockchain,
		logger:     logger,
	}

	stakeManagerConfig := &consensus.StakeManagerConfig{
		MinStakeAmount:        cfg.Consensus.MinimumStake,
		UnbondingPeriod:       time.Duration(cfg.Consensus.UnbondingPeriod) * time.Second,
		RewardPerBlock:        1000, // Set appropriate reward value
		RewardDistribution:    0.8,  // 80% to delegators, 20% to validators
		MaxDelegationsPerUser: 16,   // Set appropriate limit
	}

	// Create stake manager
	stakeManager := consensus.NewStakeManager(
		stakeManagerConfig,
		&StakeStorageImpl{db: db},
		logger,
	)
	err = stakeManager.Initialize()
	if err != nil {
		logger.Error("Failed to initialize stake manager", "error", err)
		os.Exit(1)
	}

	validatorConfig := &consensus.ValidatorManagerConfig{
		MaxValidators:          int(cfg.Consensus.ActiveValidators * 5), // Example: 5x the active count
		ActiveValidatorsCount:  int(cfg.Consensus.ActiveValidators),
		MinStake:               cfg.Consensus.MinimumStake,
		UnbondingTime:          time.Duration(cfg.Consensus.UnbondingPeriod) * time.Second,
		SlashingPenaltyPercent: int(cfg.Consensus.DoubleSignSlashRate / 100), // Convert basis points to percent
		JailTime:               time.Duration(cfg.Consensus.DowntimeJailDuration) * time.Second,
	}

	// Create validator manager
	validatorManager := consensus.NewValidatorManager(
		validatorConfig, // Use config from loaded config
		stakeManager,
		&ValidatorStorageImpl{db: db},
		logger,
	)
	err = validatorManager.Initialize()
	if err != nil {
		logger.Error("Failed to initialize validator manager", "error", err)
		os.Exit(1)
	}

	// Create consensus engine
	engine := consensus.NewDPoSEngine(
		consensus.ConvertConsensusParams(&cfg.Consensus),
		validatorManager,
		stakeManager,
		txPool,
		blockchain,
		logger,
	)

	// Start consensus engine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = engine.Start(ctx)
	if err != nil {
		logger.Error("Failed to start consensus engine", "error", err)
		os.Exit(1)
	}

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Stop the consensus engine
	logger.Info("Shutting down...")
	engine.Stop()
}

// Mock implementations for the example
type BlockchainImpl struct {
	db         storage.DB
	stateStore *state.MemoryStore
	keyManager *crypto.KeyManager
	logger     *utils.Logger
}

// CalculateStateRoot implements consensus.Blockchain.
func (b *BlockchainImpl) CalculateStateRoot(txs []types.Transaction) ([]byte, error) {
	panic("unimplemented")
}

// GetBlockByHeight implements consensus.Blockchain.
func (b *BlockchainImpl) GetBlockByHeight(height uint64) (*types.Block, error) {
	panic("unimplemented")
}

// VerifySignature implements consensus.Blockchain.
func (b *BlockchainImpl) VerifySignature(publicKey []byte, data []byte, signature []byte) bool {
	panic("unimplemented")
}

func (p *TxPoolImpl) Count() int {
	return 0
}

func (b *BlockchainImpl) GetLatestBlock() (*types.Block, error) {
	// Implementation omitted for brevity
	return nil, nil
}

func (b *BlockchainImpl) AddBlock(block *types.Block) error {
	// Implementation omitted for brevity
	return nil
}

func (b *BlockchainImpl) ValidateTransaction(tx *types.Transaction) error {
	// Implementation omitted for brevity
	return nil
}

func (b *BlockchainImpl) ApplyTransaction(tx *types.Transaction) error {
	// Implementation omitted for brevity
	return nil
}

func (b *BlockchainImpl) SignBlock(block *types.BlockHeader) ([]byte, error) {
	// Implementation omitted for brevity
	return nil, nil
}

func (b *BlockchainImpl) VerifyBlockSignature(block *types.Block) bool {
	// Implementation omitted for brevity
	return true
}

func (b *BlockchainImpl) GetOurValidator() *types.Validator {
	// Implementation omitted for brevity
	return nil
}

type TxPoolImpl struct {
	blockchain *BlockchainImpl
	logger     *utils.Logger
}

func (p *TxPoolImpl) GetTransaction(txID []byte) (*types.Transaction, error) {
	panic("unimplemented")
}

func (p *TxPoolImpl) AddTransaction(tx *types.Transaction) error {
	// Implementation omitted for brevity
	return nil
}

func (p *TxPoolImpl) RemoveTransaction(hash []byte) {
	// Implementation omitted for brevity
}

func (p *TxPoolImpl) GetPendingTransactions(limit int) []types.Transaction {
	// Implementation omitted for brevity
	return nil
}

type StakeStorageImpl struct {
	db storage.DB
}

func (s *StakeStorageImpl) SaveDelegations(delegations map[string][]*types.Stake) error {
	// Implementation omitted for brevity
	return nil
}

func (s *StakeStorageImpl) LoadDelegations() (map[string][]*types.Stake, error) {
	// Implementation omitted for brevity
	return nil, nil
}

func (s *StakeStorageImpl) SaveUnbondingRequests(requests []*types.UnbondingRequest) error {
	// Implementation omitted for brevity
	return nil
}

func (s *StakeStorageImpl) LoadUnbondingRequests() ([]*types.UnbondingRequest, error) {
	// Implementation omitted for brevity
	return nil, nil
}

type ValidatorStorageImpl struct {
	db storage.DB
}

func (s *ValidatorStorageImpl) SaveValidators(validators []*types.Validator) error {
	// Implementation omitted for brevity
	return nil
}

func (s *ValidatorStorageImpl) LoadValidators() ([]*types.Validator, error) {
	// Implementation omitted for brevity
	return nil, nil
}

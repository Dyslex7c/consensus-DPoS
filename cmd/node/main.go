package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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
	stateStore := state.NewMemoryStateStore()
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

	// Create stake manager
	stakeManager := consensus.NewStakeManager(
		&cfg.Consensus, // Use config from loaded config
		&StakeStorageImpl{db: db},
		logger,
	)
	err = stakeManager.Initialize()
	if err != nil {
		logger.Error("Failed to initialize stake manager", "error", err)
		os.Exit(1)
	}

	// Create validator manager
	validatorManager := consensus.NewValidatorManager(
		&cfg.Consensus, // Use config from loaded config
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
		&cfg.Consensus, // Use config from loaded config
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

func (b *BlockchainImpl) SignBlock(block *types.Block) ([]byte, error) {
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

func (p *TxPoolImpl) AddTransaction(tx *types.Transaction) error {
	// Implementation omitted for brevity
	return nil
}

func (p *TxPoolImpl) RemoveTransaction(hash types.Hash) {
	// Implementation omitted for brevity
}

func (p *TxPoolImpl) GetPendingTransactions(limit int) []*types.Transaction {
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

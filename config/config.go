package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// General configuration
	General struct {
		// DataDir is the directory for storing blockchain data
		DataDir string
		// LogLevel defines the logging verbosity
		LogLevel string
		// NetworkID identifies the network
		NetworkID string
	}

	// Consensus configuration
	Consensus types.ConsensusParams

	// P2P network configuration
	P2P struct {
		// ListenAddress is the address to listen for P2P connections
		ListenAddress string
		// PeerSeeds are the seed nodes to connect to
		PeerSeeds []string
		// MaxPeers is the maximum number of peers to connect to
		MaxPeers int
	}

	// API configuration
	API struct {
		// Enabled indicates whether the API server is enabled
		Enabled bool
		// ListenAddress is the address to listen for API connections
		ListenAddress string
		// CorsOrigins are the allowed CORS origins
		CorsOrigins []string
	}
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	cfg := &Config{}

	// Set default general config
	cfg.General.DataDir = "./data"
	cfg.General.LogLevel = "info"
	cfg.General.NetworkID = "dpos-testnet"

	// Set default consensus params
	cfg.Consensus = types.ConsensusParams{
		EpochLength:          100,
		ActiveValidators:     21,
		MinimumStake:         1000000,
		UnbondingPeriod:      1209600, // 14 days in seconds
		BlockTimeTarget:      5,       // 5 seconds
		MaxMissedBlocks:      50,
		DoubleSignSlashRate:  1000,  // 10% in basis points
		DowntimeSlashRate:    100,   // 1% in basis points
		DowntimeJailDuration: 86400, // 24 hours in seconds
	}

	// Set default P2P config
	cfg.P2P.ListenAddress = "0.0.0.0:26656"
	cfg.P2P.PeerSeeds = []string{}
	cfg.P2P.MaxPeers = 50

	// Set default API config
	cfg.API.Enabled = true
	cfg.API.ListenAddress = "0.0.0.0:8545"
	cfg.API.CorsOrigins = []string{"*"}

	return cfg
}

// LoadConfig loads configuration from the specified file and environment variables
func LoadConfig(configFile string) (*Config, error) {
	v := viper.New()

	// Set default config
	config := DefaultConfig()

	// If config file is specified, read it
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	} else {
		// Look for config in default locations
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.consensus-dpos-go")
		v.AddConfigPath("/etc/consensus-dpos-go")

		// Try to read config
		if err := v.ReadInConfig(); err != nil {
			// It's okay if config doesn't exist
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Set environment variable prefix
	v.SetEnvPrefix("DPOS")
	v.AutomaticEnv()

	// Map config values
	if v.IsSet("general.dataDir") {
		config.General.DataDir = v.GetString("general.dataDir")
	}
	if v.IsSet("general.logLevel") {
		config.General.LogLevel = v.GetString("general.logLevel")
	}
	if v.IsSet("general.networkID") {
		config.General.NetworkID = v.GetString("general.networkID")
	}

	// Map consensus params
	if v.IsSet("consensus.epochLength") {
		config.Consensus.EpochLength = v.GetUint64("consensus.epochLength")
	}
	if v.IsSet("consensus.activeValidators") {
		config.Consensus.ActiveValidators = uint32(v.GetInt("consensus.activeValidators"))
	}
	if v.IsSet("consensus.minimumStake") {
		config.Consensus.MinimumStake = v.GetUint64("consensus.minimumStake")
	}
	if v.IsSet("consensus.unbondingPeriod") {
		config.Consensus.UnbondingPeriod = v.GetUint64("consensus.unbondingPeriod")
	}
	if v.IsSet("consensus.blockTimeTarget") {
		config.Consensus.BlockTimeTarget = uint32(v.GetInt("consensus.blockTimeTarget"))
	}
	if v.IsSet("consensus.maxMissedBlocks") {
		config.Consensus.MaxMissedBlocks = uint32(v.GetInt("consensus.maxMissedBlocks"))
	}
	if v.IsSet("consensus.doubleSignSlashRate") {
		config.Consensus.DoubleSignSlashRate = uint16(v.GetInt("consensus.doubleSignSlashRate"))
	}
	if v.IsSet("consensus.downtimeSlashRate") {
		config.Consensus.DowntimeSlashRate = uint16(v.GetInt("consensus.downtimeSlashRate"))
	}
	if v.IsSet("consensus.downtimeJailDuration") {
		config.Consensus.DowntimeJailDuration = v.GetUint64("consensus.downtimeJailDuration")
	}

	// Map P2P config
	if v.IsSet("p2p.listenAddress") {
		config.P2P.ListenAddress = v.GetString("p2p.listenAddress")
	}
	if v.IsSet("p2p.peerSeeds") {
		config.P2P.PeerSeeds = v.GetStringSlice("p2p.peerSeeds")
	}
	if v.IsSet("p2p.maxPeers") {
		config.P2P.MaxPeers = v.GetInt("p2p.maxPeers")
	}

	// Map API config
	if v.IsSet("api.enabled") {
		config.API.Enabled = v.GetBool("api.enabled")
	}
	if v.IsSet("api.listenAddress") {
		config.API.ListenAddress = v.GetString("api.listenAddress")
	}
	if v.IsSet("api.corsOrigins") {
		config.API.CorsOrigins = v.GetStringSlice("api.corsOrigins")
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(config.General.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	return config, nil
}

func SaveConfig(config *Config, configFile string) error {
	v := viper.New()

	// Map config to viper
	v.Set("general.dataDir", config.General.DataDir)
	v.Set("general.logLevel", config.General.LogLevel)
	v.Set("general.networkID", config.General.NetworkID)

	// Map consensus params
	v.Set("consensus.epochLength", config.Consensus.EpochLength)
	v.Set("consensus.activeValidators", config.Consensus.ActiveValidators)
	v.Set("consensus.minimumStake", config.Consensus.MinimumStake)
	v.Set("consensus.unbondingPeriod", config.Consensus.UnbondingPeriod)
	v.Set("consensus.blockTimeTarget", config.Consensus.BlockTimeTarget)
	v.Set("consensus.maxMissedBlocks", config.Consensus.MaxMissedBlocks)
	v.Set("consensus.doubleSignSlashRate", config.Consensus.DoubleSignSlashRate)
	v.Set("consensus.downtimeSlashRate", config.Consensus.DowntimeSlashRate)
	v.Set("consensus.downtimeJailDuration", config.Consensus.DowntimeJailDuration)

	// Map P2P config
	v.Set("p2p.listenAddress", config.P2P.ListenAddress)
	v.Set("p2p.peerSeeds", config.P2P.PeerSeeds)
	v.Set("p2p.maxPeers", config.P2P.MaxPeers)

	// Map API config
	v.Set("api.enabled", config.API.Enabled)
	v.Set("api.listenAddress", config.API.ListenAddress)
	v.Set("api.corsOrigins", config.API.CorsOrigins)

	// Ensure directory exists
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for config file: %w", err)
	}

	// Write config to file
	v.SetConfigFile(configFile)
	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func DefaultConfigFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".consensus-DPoS", "config.yaml")
}

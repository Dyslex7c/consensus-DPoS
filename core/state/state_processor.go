package state

import (
	"errors"
	"time"

	"github.com/Dyslex7c/consensus-DPoS/core/types"
)

// StateProcessor is responsible for applying transactions to the blockchain state
type StateProcessor struct {
	// Current state of the blockchain
	state *State
	// Consensus parameters
	params types.ConsensusParams
}

// State represents the current state of the blockchain
type State struct {
	// Current height of the blockchain
	Height uint64
	// Current validators
	Validators map[string]*types.Validator // key is base64 encoded public key
	// Current stakes
	Stakes map[string]*types.Stake // key is delegator+validator (base64 encoded)
	// Account balances
	Balances map[string]uint64 // key is base64 encoded public key
	// Account nonces
	Nonces map[string]uint64 // key is base64 encoded public key
	// Current epoch
	CurrentEpoch uint64
	// Last updated timestamp
	LastUpdated time.Time
}

// NewStateProcessor creates a new state processor
func NewStateProcessor(initialState *State, params types.ConsensusParams) *StateProcessor {
	return &StateProcessor{
		state:  initialState,
		params: params,
	}
}

// ProcessBlock applies all transactions in a block to the current state
func (sp *StateProcessor) ProcessBlock(block *types.Block) error {
	// Verify block proposer is in active validator set
	proposer, exists := sp.state.Validators[string(block.Header.Proposer)]
	if !exists {
		return errors.New("block proposer is not a registered validator")
	}

	if proposer.Status != types.ValidatorStatusActive {
		return errors.New("block proposer is not an active validator")
	}

	// Apply each transaction
	for _, tx := range block.Transactions {
		if err := sp.ProcessTransaction(&tx); err != nil {
			return err
		}
	}

	// Update block height
	sp.state.Height = block.Header.Height

	// Update epoch if needed
	if block.Header.Height%sp.params.EpochLength == 0 {
		sp.state.CurrentEpoch++

		// Process epoch-related activities
		if err := sp.ProcessEpochTransition(); err != nil {
			return err
		}
	}

	// Update last updated timestamp
	sp.state.LastUpdated = block.Header.Timestamp

	return nil
}

// ProcessTransaction applies a single transaction to the state
func (sp *StateProcessor) ProcessTransaction(tx *types.Transaction) error {
	// Verify sender has enough balance
	senderKey := string(tx.Sender)
	senderBalance, exists := sp.state.Balances[senderKey]
	if !exists {
		return errors.New("sender account does not exist")
	}

	// Verify nonce
	if tx.Nonce != sp.state.Nonces[senderKey] {
		return errors.New("invalid transaction nonce")
	}

	// Process based on transaction type
	switch tx.Type {
	case types.TransactionTypeTransfer:
		return sp.processTransfer(tx, senderBalance)

	case types.TransactionTypeDelegate:
		return sp.processDelegate(tx, senderBalance)

	case types.TransactionTypeUndelegate:
		return sp.processUndelegate(tx)

	case types.TransactionTypeRegisterValidator:
		return sp.processRegisterValidator(tx, senderBalance)

	case types.TransactionTypeUnregisterValidator:
		return sp.processUnregisterValidator(tx)

	default:
		return errors.New("unknown transaction type")
	}
}

// processTransfer handles standard token transfers
func (sp *StateProcessor) processTransfer(tx *types.Transaction, senderBalance uint64) error {
	if tx.Amount > senderBalance {
		return errors.New("insufficient balance")
	}

	recipientKey := string(tx.Recipient)

	// Update sender balance
	sp.state.Balances[string(tx.Sender)] -= tx.Amount

	// Update recipient balance
	if _, exists := sp.state.Balances[recipientKey]; !exists {
		sp.state.Balances[recipientKey] = 0
	}
	sp.state.Balances[recipientKey] += tx.Amount

	// Update sender nonce
	sp.state.Nonces[string(tx.Sender)]++

	return nil
}

// processDelegate handles delegation of tokens to validators
func (sp *StateProcessor) processDelegate(tx *types.Transaction, senderBalance uint64) error {
	if tx.Amount > senderBalance {
		return errors.New("insufficient balance for delegation")
	}

	// Verify validator exists and is not tombstoned
	validatorKey := string(tx.Recipient)
	validator, exists := sp.state.Validators[validatorKey]
	if !exists {
		return errors.New("validator does not exist")
	}

	if validator.Status == types.ValidatorStatusTombstoned {
		return errors.New("cannot delegate to tombstoned validator")
	}

	// Create or update stake
	stakeKey := string(tx.Sender) + validatorKey

	var stake *types.Stake
	existingStake, exists := sp.state.Stakes[stakeKey]

	if exists {
		// Clone and modify existing stake
		stake = existingStake.Clone()
		stake.Amount += tx.Amount
		stake.UpdatedAt = tx.Timestamp
	} else {
		// Create new stake
		stake = &types.Stake{
			Delegator:           tx.Sender,
			Validator:           tx.Recipient,
			Amount:              tx.Amount,
			CreatedAt:           tx.Timestamp,
			UpdatedAt:           tx.Timestamp,
			PendingRewards:      0,
			Unbonding:           false,
			UnbondingCompleteAt: time.Time{},
		}
	}

	// Update state
	sp.state.Stakes[stakeKey] = stake
	sp.state.Balances[string(tx.Sender)] -= tx.Amount

	// Update validator
	updatedValidator := validator.Clone()
	updatedValidator.TotalStake += tx.Amount

	// If self-delegation, update self-stake
	if string(tx.Sender) == validatorKey {
		updatedValidator.SelfStake += tx.Amount
	}

	// Update voting power
	updatedValidator.VotingPower = calculateVotingPower(updatedValidator.TotalStake)

	sp.state.Validators[validatorKey] = updatedValidator

	// Update sender nonce
	sp.state.Nonces[string(tx.Sender)]++

	return nil
}

// processUndelegate handles undelegation of tokens from validators
func (sp *StateProcessor) processUndelegate(tx *types.Transaction) error {
	validatorKey := string(tx.Recipient)
	stakeKey := string(tx.Sender) + validatorKey

	// Verify stake exists
	stake, exists := sp.state.Stakes[stakeKey]
	if !exists {
		return errors.New("no delegation found for this validator")
	}

	// Verify amount
	if tx.Amount > stake.Amount {
		return errors.New("undelegation amount exceeds staked amount")
	}

	// Clone and update stake
	updatedStake := stake.Clone()
	updatedStake.Amount -= tx.Amount
	updatedStake.UpdatedAt = tx.Timestamp

	// If fully undelegating, mark for unbonding
	if updatedStake.Amount == 0 {
		updatedStake.Unbonding = true
		updatedStake.UnbondingCompleteAt = tx.Timestamp.Add(time.Duration(sp.params.UnbondingPeriod) * time.Second)
	} else if tx.Amount > 0 {
		// Create a new unbonding entry
		unbondingStake := &types.Stake{
			Delegator:           tx.Sender,
			Validator:           tx.Recipient,
			Amount:              tx.Amount,
			CreatedAt:           stake.CreatedAt,
			UpdatedAt:           tx.Timestamp,
			PendingRewards:      0, // Calculate proportional rewards if implementing
			Unbonding:           true,
			UnbondingCompleteAt: tx.Timestamp.Add(time.Duration(sp.params.UnbondingPeriod) * time.Second),
		}

		// Add to stakes with a special key
		sp.state.Stakes[stakeKey+"_unbonding"] = unbondingStake
	}

	// Update original stake
	sp.state.Stakes[stakeKey] = updatedStake

	// Update validator
	validator := sp.state.Validators[validatorKey]
	updatedValidator := validator.Clone()
	updatedValidator.TotalStake -= tx.Amount

	// If self-undelegation, update self-stake
	if string(tx.Sender) == validatorKey {
		updatedValidator.SelfStake -= tx.Amount

		// If self-stake falls below minimum, change status to inactive
		if updatedValidator.SelfStake < sp.params.MinimumStake && updatedValidator.Status == types.ValidatorStatusActive {
			updatedValidator.Status = types.ValidatorStatusInactive
		}
	}

	// Update voting power
	updatedValidator.VotingPower = calculateVotingPower(updatedValidator.TotalStake)

	sp.state.Validators[validatorKey] = updatedValidator

	// Update sender nonce
	sp.state.Nonces[string(tx.Sender)]++

	return nil
}

// processRegisterValidator handles validator registration
func (sp *StateProcessor) processRegisterValidator(tx *types.Transaction, senderBalance uint64) error {
	if tx.Amount < sp.params.MinimumStake {
		return errors.New("insufficient stake to register as validator")
	}

	if tx.Amount > senderBalance {
		return errors.New("insufficient balance for validator registration")
	}

	validatorKey := string(tx.Sender)

	// Check if validator already exists
	if _, exists := sp.state.Validators[validatorKey]; exists {
		return errors.New("validator already registered")
	}

	// Extract commission rate from transaction data
	if len(tx.Data) < 1 {
		return errors.New("missing commission rate in transaction data")
	}
	commission := uint8(tx.Data[0])

	// Create new validator
	validator := &types.Validator{
		Address:             tx.Sender, // For simplicity, using same as public key
		PublicKey:           tx.Sender,
		VotingPower:         calculateVotingPower(tx.Amount),
		TotalStake:          tx.Amount,
		SelfStake:           tx.Amount,
		Commission:          commission,
		JoinedAt:            tx.Timestamp,
		Status:              types.ValidatorStatusInactive, // Start as inactive until elected
		Uptime:              100.0,                         // Start with perfect uptime
		BlocksProposed:      0,
		BlocksValidated:     0,
		JailedUntil:         time.Time{}, // Zero time means not jailed
		MissedBlocksCounter: 0,
	}

	// Create self-delegation stake
	stake := &types.Stake{
		Delegator:           tx.Sender,
		Validator:           tx.Sender,
		Amount:              tx.Amount,
		CreatedAt:           tx.Timestamp,
		UpdatedAt:           tx.Timestamp,
		PendingRewards:      0,
		Unbonding:           false,
		UnbondingCompleteAt: time.Time{},
	}

	// Update state
	sp.state.Validators[validatorKey] = validator
	sp.state.Stakes[validatorKey+validatorKey] = stake
	sp.state.Balances[validatorKey] -= tx.Amount

	// Update sender nonce
	sp.state.Nonces[string(tx.Sender)]++

	return nil
}

// processUnregisterValidator handles validator unregistration
func (sp *StateProcessor) processUnregisterValidator(tx *types.Transaction) error {
	validatorKey := string(tx.Sender)

	// Check if validator exists
	validator, exists := sp.state.Validators[validatorKey]
	if !exists {
		return errors.New("validator not registered")
	}

	// Cannot unregister if jailed
	if validator.Status == types.ValidatorStatusJailed {
		return errors.New("cannot unregister while jailed")
	}

	// Start unbonding process for self-stake
	stakeKey := validatorKey + validatorKey
	selfStake, exists := sp.state.Stakes[stakeKey]
	if !exists {
		return errors.New("validator self-stake not found")
	}

	// Mark validator as inactive
	updatedValidator := validator.Clone()
	updatedValidator.Status = types.ValidatorStatusInactive
	sp.state.Validators[validatorKey] = updatedValidator

	// Mark self-stake for unbonding
	updatedStake := selfStake.Clone()
	updatedStake.Unbonding = true
	updatedStake.UpdatedAt = tx.Timestamp
	updatedStake.UnbondingCompleteAt = tx.Timestamp.Add(time.Duration(sp.params.UnbondingPeriod) * time.Second)
	sp.state.Stakes[stakeKey] = updatedStake

	// Update sender nonce
	sp.state.Nonces[string(tx.Sender)]++

	return nil
}

// ProcessEpochTransition handles state changes at epoch boundaries
func (sp *StateProcessor) ProcessEpochTransition() error {
	// Distribute rewards
	if err := sp.distributeRewards(); err != nil {
		return err
	}

	// Process completed unbondings
	if err := sp.processCompletedUnbondings(); err != nil {
		return err
	}

	// Update validator set
	if err := sp.updateValidatorSet(); err != nil {
		return err
	}

	// Unjail validators whose jail time has expired
	if err := sp.unjailValidators(); err != nil {
		return err
	}

	return nil
}

// distributeRewards allocates staking rewards for the epoch
func (sp *StateProcessor) distributeRewards() error {
	// Implementation would depend on reward calculation logic
	// For now, just a placeholder
	return nil
}

// processCompletedUnbondings releases tokens for completed unbonding periods
func (sp *StateProcessor) processCompletedUnbondings() error {
	now := time.Now()

	for key, stake := range sp.state.Stakes {
		if stake.Unbonding && !stake.UnbondingCompleteAt.IsZero() && now.After(stake.UnbondingCompleteAt) {
			// Return funds to delegator
			delegatorKey := string(stake.Delegator)
			sp.state.Balances[delegatorKey] += stake.Amount

			// Remove the stake
			delete(sp.state.Stakes, key)
		}
	}

	return nil
}

// updateValidatorSet selects active validators based on stake
func (sp *StateProcessor) updateValidatorSet() error {
	// Step 1: Reset all active validators to inactive
	for key, validator := range sp.state.Validators {
		if validator.Status == types.ValidatorStatusActive {
			updated := validator.Clone()
			updated.Status = types.ValidatorStatusInactive
			sp.state.Validators[key] = updated
		}
	}

	// Step 2: Create list of eligible validators (not jailed or tombstoned)
	var eligible []*types.Validator
	for _, validator := range sp.state.Validators {
		if validator.Status != types.ValidatorStatusJailed && validator.Status != types.ValidatorStatusTombstoned {
			eligible = append(eligible, validator)
		}
	}

	// Step 3: Sort by voting power (a real implementation would sort here)
	// For simplicity, we're not implementing the sort

	// Step 4: Select top N validators
	activeCount := int(sp.params.ActiveValidators)
	if len(eligible) < activeCount {
		activeCount = len(eligible)
	}

	for i := 0; i < activeCount; i++ {
		validator := eligible[i]
		updated := validator.Clone()
		updated.Status = types.ValidatorStatusActive
		sp.state.Validators[string(validator.PublicKey)] = updated
	}

	return nil
}

// unjailValidators removes jail status from validators whose jail time has expired
func (sp *StateProcessor) unjailValidators() error {
	now := time.Now()

	for key, validator := range sp.state.Validators {
		if validator.Status == types.ValidatorStatusJailed && !validator.JailedUntil.IsZero() && now.After(validator.JailedUntil) {
			updated := validator.Clone()
			updated.Status = types.ValidatorStatusInactive
			updated.JailedUntil = time.Time{} // Reset jail time
			updated.MissedBlocksCounter = 0   // Reset missed blocks counter
			sp.state.Validators[key] = updated
		}
	}

	return nil
}

// SlashValidator penalizes a validator for misbehavior
func (sp *StateProcessor) SlashValidator(validatorPubKey []byte, slashReason string, slashAmount uint16) error {
	validatorKey := string(validatorPubKey)
	validator, exists := sp.state.Validators[validatorKey]
	if !exists {
		return errors.New("validator not found")
	}

	// Calculate slash amount (basis points)
	slashFactor := float64(slashAmount) / 10000.0
	tokensToSlash := uint64(float64(validator.TotalStake) * slashFactor)

	// Apply slashing to all delegations proportionally
	for key, stake := range sp.state.Stakes {
		if string(stake.Validator) == validatorKey {
			stakeSlashAmount := uint64(float64(stake.Amount) * slashFactor)
			if stakeSlashAmount > 0 {
				updatedStake := stake.Clone()
				updatedStake.Amount -= stakeSlashAmount
				updatedStake.UpdatedAt = time.Now()
				sp.state.Stakes[key] = updatedStake
			}
		}
	}

	// Update validator
	updatedValidator := validator.Clone()
	updatedValidator.TotalStake -= tokensToSlash
	if string(validator.PublicKey) == validatorKey {
		selfSlashAmount := uint64(float64(validator.SelfStake) * slashFactor)
		updatedValidator.SelfStake -= selfSlashAmount
	}
	updatedValidator.VotingPower = calculateVotingPower(updatedValidator.TotalStake)

	// If double signing, tombstone the validator
	if slashReason == "double_signing" {
		updatedValidator.Status = types.ValidatorStatusTombstoned
	} else if slashReason == "downtime" {
		// For downtime, jail the validator
		updatedValidator.Status = types.ValidatorStatusJailed
		updatedValidator.JailedUntil = time.Now().Add(time.Duration(sp.params.DowntimeJailDuration) * time.Second)
	}

	sp.state.Validators[validatorKey] = updatedValidator

	return nil
}

// calculateVotingPower determines a validator's voting weight based on stake
func calculateVotingPower(stake uint64) uint64 {
	// Simple 1:1 relationship between stake and voting power
	// More complex implementations could use different formulas
	return stake
}

// GetState returns the current state
func (sp *StateProcessor) GetState() *State {
	return sp.state
}

// GetParams returns the consensus parameters
func (sp *StateProcessor) GetParams() types.ConsensusParams {
	return sp.params
}

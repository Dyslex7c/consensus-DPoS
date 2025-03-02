package types

func (v *Validator) Clone() *Validator {
	if v == nil {
		return nil
	}

	clone := &Validator{
		VotingPower:         v.VotingPower,
		TotalStake:          v.TotalStake,
		SelfStake:           v.SelfStake,
		Commission:          v.Commission,
		JoinedAt:            v.JoinedAt,
		Status:              v.Status,
		Uptime:              v.Uptime,
		BlocksProposed:      v.BlocksProposed,
		BlocksValidated:     v.BlocksValidated,
		JailedUntil:         v.JailedUntil,
		MissedBlocksCounter: v.MissedBlocksCounter,
	}

	if v.Address != nil {
		clone.Address = make([]byte, len(v.Address))
		copy(clone.Address, v.Address)
	}

	if v.PublicKey != nil {
		clone.PublicKey = make([]byte, len(v.PublicKey))
		copy(clone.PublicKey, v.PublicKey)
	}

	return clone
}

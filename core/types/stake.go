package types

func (s *Stake) Clone() *Stake {
	if s == nil {
		return nil
	}

	clone := &Stake{
		Delegator:           append([]byte(nil), s.Delegator...),
		Validator:           append([]byte(nil), s.Validator...),
		Amount:              s.Amount,
		CreatedAt:           s.CreatedAt,
		UpdatedAt:           s.UpdatedAt,
		PendingRewards:      s.PendingRewards,
		Unbonding:           s.Unbonding,
		UnbondingCompleteAt: s.UnbondingCompleteAt,
	}

	if s.Delegator != nil {
		clone.Delegator = make([]byte, len(s.Delegator))
		copy(clone.Delegator, s.Delegator)
	}

	if s.Validator != nil {
		clone.Validator = make([]byte, len(s.Validator))
		copy(clone.Validator, s.Validator)
	}

	return clone
}

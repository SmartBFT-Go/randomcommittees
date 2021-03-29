// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package cs

import (
	"math/big"

	cs "github.com/SmartBFT-Go/randomcommittees/internal"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
)

func NewCommitteeSelection(logger committee.Logger) *cs.CommitteeSelection {
	return &cs.CommitteeSelection{
		SelectCommittee: func(config committee.Config, seed []byte) []int32 {
			failureChance := big.NewRat(1, config.InverseFailureChance)
			size := cs.CommitteeSize(int64(len(config.Nodes)), config.FailedTotalNodesPercentage, *failureChance)
			return cs.SelectCommittee(config, seed, size)
		},
		Logger: logger,
	}
}

func StateFromBytes(b []byte) (*cs.State, error) {
	s := &cs.State{}
	return s, s.Initialize(b)
}

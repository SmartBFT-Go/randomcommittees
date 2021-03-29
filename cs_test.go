// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package cs_test

import (
	"testing"

	cs "github.com/SmartBFT-Go/randomcommittees"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
)

func TestNewCommitteeSelection(t *testing.T) {
	// Check that the implementation correctly implements the interface
	var myCommitteeSelection committee.Selection
	myCommitteeSelection = cs.NewCommitteeSelection(nil)
	_ = myCommitteeSelection
}

// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package cs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.uber.org/zap"

	cs "github.com/SmartBFT-Go/randomcommittees"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
)

func TestNewCommitteeSelection(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	// Check that the implementation correctly implements the interface
	var myCommitteeSelection committee.Selection
	myCommitteeSelection = cs.NewCommitteeSelection(logger.Sugar())
	_ = myCommitteeSelection

	s, err := cs.StateFromBytes(nil)
	assert.NotNil(t, s)
	assert.NoError(t, err)
}

// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package committee

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigMarshalUnmarshal(t *testing.T) {
	cm := &Config{
		FailedTotalNodesPercentage: 1,
		MandatoryNodes:             []int32{1, 2, 3},
		ExcludedNodes:              []int32{4, 5, 6},
		InverseFailureChance:       2,
		MinimumLifespan:            3,
		Nodes:                      Nodes{{ID: 7, PubKey: []byte{1, 2, 3}}},
		Weights:                    []Weight{{ID: 1, Weight: 25}, {ID: 2, Weight: 25}, {ID: 3, Weight: 50}},
	}

	cm2 := &Config{}
	err := cm2.Unmarshal(cm.Marshal())
	assert.NoError(t, err)
	assert.Equal(t, cm, cm2)
}

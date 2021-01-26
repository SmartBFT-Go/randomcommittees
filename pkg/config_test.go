package pvss

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
		Nodes:                      []int32{7, 8, 9},
		Weights:                    []Weight{{ID: 1, Weight: 25}, {ID: 2, Weight: 25}, {ID: 3, Weight: 50}},
	}

	cm2 := &Config{}
	cm2.Unmarshal(cm.Marshal())
	assert.Equal(t, cm, cm2)
}

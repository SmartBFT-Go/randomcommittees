/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommitteeSize(t *testing.T) {
	type args struct {
		totalNodeCount             int64
		failedTotalNodesPercentage int64
		failureChance              big.Rat
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "4 nodes",
			want: 4,
			args: args{
				failedTotalNodesPercentage: 33,
				failureChance:              *big.NewRat(1, 100),
				totalNodeCount:             4,
			},
		},
		{
			name: "11 nodes",
			want: 4,
			args: args{
				failedTotalNodesPercentage: 1,
				failureChance:              *big.NewRat(1, 100),
				totalNodeCount:             11,
			},
		},
		{
			name: "1000 nodes 33% byzantine",
			want: 1000,
			args: args{
				failedTotalNodesPercentage: 33,
				failureChance:              *big.NewRat(1, 100),
				totalNodeCount:             1000,
			},
		},
		{
			name: "1000 nodes 10% byzantine, slim failure chance",
			want: 79,
			args: args{
				failedTotalNodesPercentage: 10,
				failureChance:              *big.NewRat(1, 1000000000),
				totalNodeCount:             1000,
			},
		},
		{
			name: "5000 nodes 20% byzantine, moderate failure chance",
			want: 223,
			args: args{
				failedTotalNodesPercentage: 20,
				failureChance:              *big.NewRat(1, 1000000),
				totalNodeCount:             5000,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			committeeSize := CommitteeSize(tt.args.totalNodeCount, tt.args.failedTotalNodesPercentage, tt.args.failureChance)
			if committeeSize != tt.want {
				t.Errorf("CommitteeSize() = %v, want %v", committeeSize, tt.want)
			}
			byzantineRatio := float64(tt.args.failedTotalNodesPercentage) / 100
			failureChance, _ := tt.args.failureChance.Float64()
			p := 1 - hyperGeomRangeSum(tt.args.totalNodeCount, int64(committeeSize), byzantineRatio)
			assert.LessOrEqual(t, p, failureChance)
		})
	}
}

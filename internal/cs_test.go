/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	mathrand "math/rand"
	"reflect"
	"testing"
	"time"

	cs "github.com/SmartBFT-Go/randomcommittees"
	. "github.com/SmartBFT-Go/randomcommittees/internal"
	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	mathrand.Seed(time.Now().Unix())
}

func TestNewCommitteeSelection(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger, _ := logConfig.Build()
	cs.NewCommitteeSelection(logger.Sugar())
}

func TestSelectCommittee(t *testing.T) {
	randomSeed := make([]byte, 8)
	binary.BigEndian.PutUint64(randomSeed, uint64(time.Now().Unix()))

	t.Log("Random seed:", hex.EncodeToString(randomSeed))

	type args struct {
		config committee.Config
		seed   []byte
		size   int
	}
	tests := []struct {
		name string
		args args
		want []int32
	}{
		{
			name: "10 out of 10",
			args: args{
				seed: []byte{1, 2, 3, 4, 5},
				config: committee.Config{
					Nodes: nodes(10),
				},
				size: 10,
			},
			want: []int32{5, 0, 2, 1, 7, 4, 3, 9, 8, 6},
		},
		{
			name: "No weight supplied means uniform",
			args: args{
				seed: []byte{1, 2, 3, 4, 5},
				config: committee.Config{
					Nodes: nodes(100),
				},
				size: 10,
			},
			want: []int32{45, 55, 57, 13, 73, 6, 74, 47, 37, 5},
		},
		{
			name: "Honor weights",
			args: args{
				seed: []byte{1, 2, 3, 4, 5},
				config: committee.Config{
					Nodes: nodes(100),
					Weights: []committee.Weight{
						{
							ID:     1,
							Weight: 1 << 30,
						},
					},
				},
				size: 10,
			},
			want: []int32{1, 51, 99, 26, 0, 83, 19, 82, 55, 67},
		},
		{
			name: "Honor mandatory",
			args: args{
				seed: randomSeed,
				config: committee.Config{
					Nodes:          nodes(100),
					MandatoryNodes: []int32{10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
				},
				size: 10,
			},
			want: []int32{10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		},
		{
			name: "Honor excluded",
			args: args{
				seed: []byte{0, 0, 0, 0, 96, 92, 229, 72},
				config: committee.Config{
					Nodes:         nodes(10),
					ExcludedNodes: []int32{0, 1, 2, 3, 4, 5, 6},
				},
				size: 3,
			},
			want: []int32{7, 8, 9},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectCommittee(tt.args.config, tt.args.seed, tt.args.size); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SelectCommittee() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommitteeSelection(t *testing.T) {
	network := createNetwork(t, 11)

	var emptyStates []committee.State
	for i := 0; i < len(network); i++ {
		emptyStates = append(emptyStates, &State{})
	}

	a := network.Process(t, emptyStates, committee.Input{},
		assertEqualState, func(t *testing.T, a []stateFeedback) {
			// Nothing changed yet since the first node hasn't sent messages to the rest
			for _, e := range a {
				assert.Empty(t, e.s.ToBytes())
				assert.Empty(t, e.f.ReconShares)
				// Everyone has feedback
				assert.NotNil(t, e.f.Commitment)
				assert.Empty(t, e.f.NextCommittee)
			}
		})

	for i := 0; i <= ((len(network) - 1) / 3); i++ {
		// Initialize the state of some parties from the previous state,
		// to simulate a crash and recovery
		network.MaybeRestart(t, a[mathrand.Int()%len(network)].s.ToBytes(), a[i].s)

		// Take the feedback of the 'i' node
		c := a[i].f.Commitment
		// And use it in the i-th round

		// First verify it
		for _, n := range network {
			err := n.VerifyCommitment(*c)
			assert.NoError(t, err)
		}

		a = network.Process(t, a.states(), committee.Input{
			Commitments: []committee.Commitment{*c},
		},
			assertEqualState, func(t *testing.T, a []stateFeedback) {
				for j, e := range a {
					// We do not send ReconShares unless it is the last round
					if i == ((len(network) - 1) / 3) {
						assert.NotEmpty(t, t, e.f.ReconShares)
					} else {
						assert.Empty(t, e.f.ReconShares)
					}

					// Everyone has commitment feedback but the 'i' node
					if j == i || j < i {
						assert.Nil(t, e.f.Commitment)
					} else {
						assert.NotNil(t, e.f.Commitment)
					}
					assert.Empty(t, e.f.NextCommittee)
				}
			})
	}

	var reconShares []committee.ReconShare

	for _, e := range a {
		reconShares = append(reconShares, e.f.ReconShares...)
	}

	// Verify all ReconShares
	for _, n := range network {
		for _, rcs := range reconShares {
			err := n.VerifyReconShare(rcs)
			assert.NoError(t, err)
		}
	}

	network.Process(t, a.states(), committee.Input{
		ReconShares: reconShares,
		NextConfig: committee.Config{
			InverseFailureChance:       100,
			FailedTotalNodesPercentage: 5,
			Nodes: committee.Nodes{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}, {ID: 5}, {ID: 6},
				{ID: 7}, {ID: 8}, {ID: 9}, {ID: 10}, {ID: 11}},
		},
	},
		assertEqualState, func(t *testing.T, a []stateFeedback) {
			for _, e := range a {
				assert.Equal(t, []int32{1, 2, 3, 4}, e.f.NextCommittee)
			}
		})

	seeds := make(map[string]struct{})
	for _, n := range network {
		seeds[hex.EncodeToString(n.latestSeed)] = struct{}{}
	}

	assert.Len(t, seeds, 1)

}

func assertEqualState(t *testing.T, a []stateFeedback) {
	states := make(map[string]*State)
	for _, e := range a {
		states[base64.StdEncoding.EncodeToString(e.s.ToBytes())] = e.s.(*State)
	}
	require.Len(t, states, 1)
}

type stateFeedbacks []stateFeedback

func (sfs stateFeedbacks) states() []committee.State {
	var res []committee.State
	for _, sf := range sfs {
		res = append(res, sf.s)
	}
	return res
}

type stateFeedback struct {
	s committee.State
	f committee.Feedback
}

type node struct {
	*CommitteeSelection
	id         int32
	pk         []byte
	sk         []byte
	latestSeed []byte
}

type network []node

func (net network) Process(t *testing.T, states []committee.State, input committee.Input, preds ...func(t *testing.T, a []stateFeedback)) stateFeedbacks {
	var res []stateFeedback

	for i, n := range net {
		f, s, err := n.Process(states[i], input)
		assert.NoError(t, err)
		res = append(res, stateFeedback{s: s, f: f})
	}

	for _, pred := range preds {
		pred(t, res)
	}

	return res
}

func (net network) MaybeRestart(t *testing.T, state []byte, s committee.State) {
	for _, n := range net {
		if mathrand.Int()%2 == 0 {
			continue
		}
		n.CommitteeSelection = &CommitteeSelection{
			Logger:          n.CommitteeSelection.Logger,
			SelectCommittee: n.CommitteeSelection.SelectCommittee,
		}
		n.CommitteeSelection.Logger.Infof("Restarting")
		assert.NoError(t, n.Initialize(n.id, n.sk, net.nodes()))
		// Wipe out the existing state
		assert.NoError(t, s.Initialize(nil))
		// Recover it
		assert.NoError(t, s.Initialize(state))
	}
}

func (net network) nodes() committee.Nodes {
	var res committee.Nodes

	for _, n := range net {
		res = append(res, committee.Node{
			ID:     n.id,
			PubKey: n.pk,
		})
	}

	return res
}

func createNetwork(t *testing.T, size int) network {
	idGen := make(idGenerator)
	mathrand.Seed(time.Now().Unix())

	var net network

	for i := 0; i < size; i++ {
		id := idGen.generateID()

		t.Log("id:", id)

		logConfig := zap.NewDevelopmentConfig()
		logger, _ := logConfig.Build()
		logger = logger.With(zap.String("t", t.Name())).With(zap.Int64("id", int64(id)))

		latestSeed := make([]byte, 32)

		cs := &CommitteeSelection{
			SelectCommittee: func(_ committee.Config, seed []byte) []int32 {
				copy(latestSeed, seed)
				return []int32{1, 2, 3, 4}
			},
			Logger: logger.Sugar(),
		}

		pk, sk, err := cs.GenerateKeyPair(rand.Reader)
		assert.NoError(t, err)

		net = append(net, node{
			latestSeed:         latestSeed,
			CommitteeSelection: cs,
			id:                 id,
			pk:                 pk,
			sk:                 sk,
		})
	}

	for _, n := range net {
		n.Initialize(n.id, n.sk, net.nodes())
	}

	return net
}

type idGenerator map[int32]struct{}

func (ig idGenerator) generateID() int32 {
	for {
		n := mathrand.Uint32() >> 16
		_, exists := ig[int32(n)]
		if exists {
			continue
		}
		ig[int32(n)] = struct{}{}
		return int32(n)
	}
}

func nodes(n int) committee.Nodes {
	var res committee.Nodes
	for i := 0; i < n; i++ {
		res = append(res, committee.Node{
			ID:     int32(i),
			PubKey: []byte{byte(i)},
		})
	}
	return res
}

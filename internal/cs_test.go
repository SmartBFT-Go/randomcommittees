/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"crypto/rand"
	mathrand "math/rand"
	"testing"
	"time"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func init() {
	mathrand.Seed(time.Now().Unix())
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

	var sharedState []byte

	for i := 0; i <= ((len(network) - 1) / 3); i++ {
		// Initialize the state of some parties from the previous state,
		// to simulate a crash and recovery
		network.MaybeRestart(t, sharedState, a[i].s)

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
					if j == i {
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
	},
		assertEqualState, func(t *testing.T, a []stateFeedback) {
			for _, e := range a {
				assert.Empty(t, e.f.NextCommittee)
			}
		})

}

func assertEqualState(t *testing.T, a []stateFeedback) {
	stateDigests := make(map[string]struct{})
	for _, e := range a {
		stateDigests[digest(e.s.ToBytes())] = struct{}{}
	}
	assert.Len(t, stateDigests, 1)
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
	id int32
	pk []byte
	sk []byte
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

		cs := &CommitteeSelection{
			SelectCommittee: simpleCommitteeSelector,
			Logger:          logger.Sugar(),
		}

		pk, sk, err := cs.GenerateKeyPair(rand.Reader)
		assert.NoError(t, err)

		net = append(net, node{
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

func simpleCommitteeSelector(config committee.Config, seed []byte) []int32 {
	return nil
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

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

func TestCommitteeSelection(t *testing.T) {
	network := createNetwork(t, 7)

	feedback, state, err := network[0].Process(&State{}, committee.Input{})
	assert.NoError(t, err)

	// Nothing changed yet since the first node hasn't sent messages to the rest
	assert.Empty(t, state.ToBytes())
	assert.Empty(t, feedback.ReconShares)
	assert.NotNil(t, feedback.Commitment)
	assert.Empty(t, feedback.NextCommittee)

	network.Process(t, state, committee.Input{
		ReconShares: feedback.ReconShares,
		Commitments:[]committee.Commitment{*feedback.Commitment},
	})
}

type node struct {
	*CommitteeSelection
	id int32
	pk []byte
	sk []byte
}

type network []node

func (net network) Process(t *testing.T, state committee.State, input committee.Input) []struct{committee.State; committee.Feedback}{
	var res []struct{committee.State; committee.Feedback}
	for _, n := range net {
		f, s, err := n.Process(state, input)
		assert.NoError(t, err)
		res = append(res, struct{committee.State; committee.Feedback}{
			s, f,
		})
	}
	return res
}

func (net network) nodes() committee.Nodes {
	var res committee.Nodes

	for _, n := range net {
		res = append(res, committee.Node{
			ID:     int32(n.id),
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

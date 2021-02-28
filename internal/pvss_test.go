/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
)

func TestDLEQ(t *testing.T) {
	g1 := suite.Point().Pick(suite.RandomStream())
	g2 := suite.Point().Pick(suite.RandomStream())
	scalar := suite.Scalar().Pick(suite.RandomStream())
	h1 := suite.Point().Mul(scalar, g1)
	h2 := suite.Point().Mul(scalar, g2)

	dleq := DLEQ{
		G1: g1,
		G2: g2,
	}

	proof, err := dleq.Prove(scalar)
	assert.NoError(t, err)

	dleq.H1 = h1
	dleq.H2 = h2

	err = dleq.Verify(proof)
	assert.NoError(t, err)
}

func TestCommitVerify(t *testing.T) {

	badPoint := suite.Point().Pick(suite.XOF([]byte("bla bla")))
	badPointBytes, err := badPoint.MarshalBinary()
	assert.NoError(t, err)

	for _, testCase := range []struct {
		description string
		mutateProof func(SerializedProofs) SerializedProofs
		expectedErr string
	}{
		{
			description: "all good",
			mutateProof: func(sp SerializedProofs) SerializedProofs {
				return sp
			},
		},
		{
			description: "bad A1",
			expectedErr: "a1 != g1^r * h1^c",
			mutateProof: func(sp SerializedProofs) SerializedProofs {
				proofs := sp.Proofs
				sp.Proofs = nil

				for _, proof := range proofs {
					fakeSerializedProof := SerializedProof{
						A1: badPointBytes,
						A2: proof.A2,
						R:  proof.R,
					}
					sp.Proofs = append(sp.Proofs, fakeSerializedProof)
				}
				return sp
			},
		},
		{
			description: "bad A2",
			expectedErr: "a1 != g1^r * h1^c",
			mutateProof: func(sp SerializedProofs) SerializedProofs {
				proofs := sp.Proofs
				sp.Proofs = nil

				for _, proof := range proofs {
					fakeSerializedProof := SerializedProof{
						A1: proof.A1,
						A2: badPointBytes,
						R:  proof.R,
					}
					sp.Proofs = append(sp.Proofs, fakeSerializedProof)
				}
				return sp
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			sk1 := suite.Scalar().Pick(suite.RandomStream())
			pk1 := h.Clone().Mul(sk1, nil)

			sk2 := suite.Scalar().Pick(suite.RandomStream())
			pk2 := h.Clone().Mul(sk2, nil)

			sk3 := suite.Scalar().Pick(suite.RandomStream())
			pk3 := h.Clone().Mul(sk3, nil)

			publicKeys := []kyber.Point{pk1, pk2, pk3}

			pvss := PVSS{}
			err := pvss.Commit(3, publicKeys)
			assert.NoError(t, err)

			pvss.Proofs = testCase.mutateProof(pvss.Proofs)
			err = pvss.VerifyCommit(publicKeys)

			if testCase.expectedErr != "" {
				assert.EqualError(t, err, testCase.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCommitDecryptVerify(t *testing.T) {
	sk := suite.Scalar().Pick(suite.RandomStream())
	pk := suite.Point().Mul(sk, h)

	pvss := PVSS{}
	err := pvss.Commit(1, []kyber.Point{pk})
	assert.NoError(t, err)

	e := pvss.EncryptedEvaluations[0]

	d, proof, err := DecryptShare(sk, e)
	assert.NoError(t, err)

	err = VerifyDecShare(pk, d, e, proof)
	assert.NoError(t, err)
}

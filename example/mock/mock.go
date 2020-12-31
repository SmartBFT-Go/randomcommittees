// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mock

import (
	"io"

	pvss "github.com/SmartBFT-Go/randomcommittees/pkg"
)

type CommitteeSelectionMock struct {
}

func (m *CommitteeSelectionMock) GeneratePrivateKey(rand io.Reader) (pvss.PublicKey, pvss.PrivateKey, error) {
	return nil, nil, nil
}

func (m *CommitteeSelectionMock) Initialize(ID uint32, PrivateKey []byte) error {
	return nil
}

func (m *CommitteeSelectionMock) Process(input pvss.Input) pvss.Output {
	return pvss.Output{}
}

func (m *CommitteeSelectionMock) VerifyCommitment(commitment pvss.Commitment, key pvss.PublicKey) error {
	return nil
}

func (m *CommitteeSelectionMock) VerifyReconShare(share pvss.ReconShare, key pvss.PublicKey) error {
	return nil
}

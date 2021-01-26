// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package pvss

import "io"

// CommitteeSelection is an interface that describes the API of the committee selection library
type CommitteeSelection interface {
	// GeneratePrivateKey generates a private key for an instance using the given randomness
	GenerateKeyPair(rand io.Reader) (PublicKey, PrivateKey, error, error)
	// Initialize initializes the committee selection instance with the given identifier and private key
	Initialize(ID uint32, PrivateKey []byte) error
	// Process interacts with the committee selection and feeds it with events of other remote instances from Input,
	// and receives feedback on a committee change or requests of messages to be sent via Feedback.
	// The operation operates on the given state and the new state is returned.
	Process(State, Input) (Feedback, State)
	// VerifyCommitment should be called whenever the node receives a commitment
	// and before passing it to the library or persisting it
	VerifyCommitment(Commitment, PublicKey) error
	// VerifyReconShare should be called whenever the node receives a ReconShare
	// and before passing it to the library or persisting it
	VerifyReconShare(ReconShare, PublicKey) error
}

type committeeSelection struct {
}

func (c *committeeSelection) GenerateKeyPair(rand io.Reader) (PublicKey, PrivateKey, error, error) {
	panic("implement me")
}

func (c *committeeSelection) Initialize(ID uint32, PrivateKey []byte) error {
	panic("implement me")
}

func (c *committeeSelection) Process(state State, input Input) (Feedback, State) {
	panic("implement me")
}

func (c *committeeSelection) VerifyCommitment(commitment Commitment, key PublicKey) error {
	panic("implement me")
}

func (c *committeeSelection) VerifyReconShare(share ReconShare, key PublicKey) error {
	panic("implement me")
}

func New() *committeeSelection {
	return &committeeSelection{}
}

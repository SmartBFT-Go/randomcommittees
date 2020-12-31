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
	// and receives feedback on a committee change or requests of messages to be sent via Output.
	Process(Input) Output
	// VerifyCommitment should be called whenever the node receives a commitment
	// and before passing it to the library or persisting it
	VerifyCommitment(Commitment, PublicKey) error
	// VerifyReconShare should be called whenever the node receives a ReconShare
	// and before passing it to the library or persisting it
	VerifyReconShare(ReconShare, PublicKey) error
}

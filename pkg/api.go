// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package pkg

// Commitment represents a commitment to randomness of a node
type Commitment struct {
	Data  []byte // Data should be persisted for future initialization
	Proof []byte // Proof denotes the proof the data was honestly computed
	From  uint32 // From who this commitment was sent
}

// ReconShare represents a share for reconstructing the randomness of a node
type ReconShare struct {
	Data  []byte // Data should be persisted for future initialization
	Proof []byte // Proof denotes the proof the data was honestly computed
	From  uint32 // From who this ReconShare was sent
	About uint32 // About denotes whose randomness are we reconstructing
}

// Config is the configuration of a committee
type Config struct {
	ID              uint32   // ID is our own identifier
	Committee       []uint32 // The current committee
	Nodes           []uint32 // All nodes
	MinimumLifespan uint32   // How many consensus rounds at minimum the committee remains
}

// State denotes the data structures that we should persist and input to the committee selection at each round
type State struct {
	NextCommittee Config       // NextCommittee denotes the configuration of the next committee, if applicable
	Commitments   []Commitment // Commitments is the set of commitments in chronological order
	Round         uint32       // Which round are we in, starting from 1
}

// Input is what the committee selection library consumes each round
type Input struct {
	State         State        // Current state the committee acts on
	ReconShares   []ReconShare // ReconShares denote the ReconShares received from all nodes if applicable
	ExcludedNodes []uint32     // Nodes we wish not to be included in the next committee
}

// Outputs denotes the action the committee selection library wants us to perform,
// namely to send a Commitment or ReconShares or to notify that a new committee has been selected
type Output struct {
	Commitment    *Commitment  // Commitment to broadcast, if applicable
	ReconShares   []ReconShare // ReconShares to broadcast, if applicable
	NextCommittee []uint32     // The next committee, if applicable
	NextState     State        // The next state the committee will act on
}

// CommitteeSelection is an interface that describes the API of the committee selection library
type CommitteeSelection interface {
	// VerifyCommitment should be called whenever the node receives a commitment
	// and before passing it to the library or persisting it
	VerifyCommitment(Commitment) error
	// VerifyReconShare should be called whenever the node receives a ReconShare
	// and before passing it to the library or persisting it
	VerifyReconShare(ReconShare) error
	// Step interacts with the committee selection and feeds it with events of other remote instances from Input,
	// and receives feedback on a committee change or requests of messages to be sent via Output.
	Step(Input) Output
}

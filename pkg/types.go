// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package pvss

type PublicKey []byte

type PrivateKey []byte

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
	About uint32 // About denotes whose randomness are we reconstructing
}

// Config is the configuration of a committee
type Config struct {
	// Nodes denotes the identifiers of all nodes
	// the committee can be selected from
	Nodes []uint32
	// How many consensus rounds at minimum the committee remains
	MinimumLifespan uint32
	// InverseFailureChance is 1/p where p is the probability
	// to select more than a third
	// of failed nodes to the committee.
	// The higher this number is, the larger the committee.
	// The lower this number is, the bigger chance to select
	// a committee with too many failed nodes.
	InverseFailureChance uint64
	// ExcludedNodes are nodes the current committee decided
	// not to be included in this committee
	ExcludedNodes []uint32
	// MandatoryNodes are nodes that current committee decided
	// that must be in this committee
	MandatoryNodes []uint32
}

// State denotes the data structures that we should persist
// and input to the committee selection at each round.
type State interface {
	Initialize([]byte) error
	ToBytes() []byte
}

// Input is what the committee selection library consumes each round
type Input struct {
	// State is the state the committee acts on
	State State
	// Commitments denotes commitments arriving from nodes
	Commitments []Commitment
	// ReconShares denote the ReconShares received from all nodes if applicable
	ReconShares []ReconShare
	// NextConfig is the configuration of the next committee selection if applicable
	NextConfig Config
}

// Outputs denotes the action the committee selection library wants us to perform,
// namely to send a Commitment or ReconShares or to notify that a new committee has been selected
type Output struct {
	Commitment    *Commitment  // Commitment to broadcast, if applicable
	ReconShares   []ReconShare // ReconShares to broadcast, if applicable
	NextCommittee []uint32     // The next committee, if applicable. It may be equal to the current committee
	NextState     State        // The next state the committee will act on
}

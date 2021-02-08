package cs

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/kyber/v3/suites"
)

var (
	suite = suites.MustFind("Ed25519")
	g     = suite.Point().Base()
	h     = suite.Point().Pick(suite.XOF([]byte("Random Committee Selection")))
)

type CommitteeSelection struct {
	// Configuration
	id      uint32
	sk      kyber.Scalar
	pk      kyber.Point
	pubKeys []kyber.Point
	// State
	commitment          *Commitment
	commitmentInRawForm *committee.Commitment
}

func (cs *CommitteeSelection) GenerateKeyPair(rand io.Reader) ([]byte, []byte, error) {
	sk := suite.Scalar().Pick(suite.RandomStream())
	pk := suite.Point().Mul(sk, nil)
	pkRaw, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling public key: %v", err)
	}
	skRaw, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling private key: %v", err)
	}
	return pkRaw, skRaw, nil
}

func (cs *CommitteeSelection) Initialize(ID uint32, privateKey []byte, nodes committee.Nodes) error {
	sk := suite.Scalar()
	if err := sk.UnmarshalBinary(privateKey); err != nil {
		return fmt.Errorf("failed unmarshaling secret key: %v", err)
	}

	cs.sk = sk
	cs.pk = suite.Point().Mul(cs.sk, nil)
	cs.id = ID

	pkRaw, err := cs.pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed marshaling our public key: %v", err)
	}

	// Are we in the nodes at all?
	if err := IsNodeInConfig(cs.id, pkRaw, nodes); err != nil {
		return err
	}

	// Initialize public keys in EC point form
	for _, pubKey := range nodes.PubKeys() {
		pk := suite.Point()
		if err := pk.UnmarshalBinary(pubKey); err != nil {
			return fmt.Errorf("invalid public key %s: %v", base64.StdEncoding.EncodeToString(pubKey), err)
		}
		cs.pubKeys = append(cs.pubKeys, pk)
	}

	return nil
}

// IsNodeInConfig returns whether the given node is in the config.
func IsNodeInConfig(id uint32, expectedPubKey []byte, nodes committee.Nodes) error {
	for _, node := range nodes {
		if node.ID != int32(id) {
			continue
		}
		if bytes.Equal(node.PubKey, expectedPubKey) {
			return nil
		}
		return fmt.Errorf("expected public key %s but found %s",
			base64.StdEncoding.EncodeToString(expectedPubKey),
			base64.StdEncoding.EncodeToString(node.PubKey))
	}
	return fmt.Errorf("could not find ID %d among %v", id, nodes)
}

func VerifyConfig(config committee.Config) error {
	for _, pubKey := range config.Nodes.PubKeys() {
		if err := suite.Point().UnmarshalBinary(pubKey); err != nil {
			return fmt.Errorf("invalid public key %s: %v", base64.StdEncoding.EncodeToString(pubKey), err)
		}
	}

	return nil
}

func (cs *CommitteeSelection) Process(state committee.State, input committee.Input) (committee.Feedback, committee.State, error) {
	feedback := committee.Feedback{}
	// Search for a commitment among the current state.
	// If we found a commitment in the current state, then load it to avoid computing it.
	commitments := state.(*State).Commitments
	if err := cs.loadOurCommitment(commitments); err != nil {
		return committee.Feedback{}, nil, err
	}

	// Prepare a fresh commitment if we haven't found one in the current committee.
	if cs.commitment == nil {
		if err := cs.prepareCommitment(); err != nil {
			return committee.Feedback{}, nil, err
		}
	}

	// Assign the commitment to be sent
	feedback.Commitment = cs.commitmentInRawForm

	return feedback, state, nil

}

func (cs *CommitteeSelection) VerifyCommitment(commitment committee.Commitment, key committee.PublicKey) error {
	panic("implement me")
}

func (cs *CommitteeSelection) VerifyReconShare(share committee.ReconShare, key committee.PublicKey) error {
	panic("implement me")
}

func (cs *CommitteeSelection) loadOurCommitment(commitments []Commitment) error {
	for _, cmt := range commitments {
		if cs.id == uint32(cmt.From) {
			cs.commitment = &Commitment{
				From:        cmt.From,
				Commitments: cmt.Commitments,
				EncShares:   cmt.EncShares,
			}
			rawCommitment, err := cs.commitment.ToRawForm(cs.id)
			if err != nil {
				return fmt.Errorf("failed serializing commitment to its raw form: %v", err)
			}
			cs.commitmentInRawForm = &rawCommitment
		}
	}

	return nil
}

func (cs *CommitteeSelection) prepareCommitment() error {
	shares, commitments, err := cs.commit()
	if err != nil {
		return fmt.Errorf("failed creating commitment: %v", err)
	}

	commitment := Commitment{
		From:        int32(cs.id),
		EncShares:   shares,
		Commitments: commitments,
	}

	rawCommitment, err := commitment.ToRawForm(cs.id)
	if err != nil {
		return fmt.Errorf("failed computing commitment: %v", err)
	}

	cs.commitment = &commitment
	cs.commitmentInRawForm = &rawCommitment

	return nil
}

func (cs *CommitteeSelection) commit() (shares []*pvss.PubVerShare, commitments []kyber.Point, err error) {
	pubKeys := cs.pubKeys
	n := len(pubKeys)
	f := (n - 1) / 3
	t := f + 1

	secret := suite.Scalar().Pick(suite.RandomStream())

	shares, commit, err := pvss.EncShares(suite, h, pubKeys, secret, t)
	if err != nil {
		return nil, nil, fmt.Errorf("failed computing encryption shares: %v", err)
	}

	_, commitments = commit.Info()

	return shares, commitments, nil
}

type State struct {
	Commitments []Commitment
}

func (s *State) Initialize(bytes []byte) error {
	rs := &RawState{}
	if _, err := asn1.Unmarshal(bytes, rs); err != nil {
		return fmt.Errorf("failed unmarshaling state bytes(%s): %v", base64.StdEncoding.EncodeToString(bytes), err)
	}

	if err := s.loadCommitments(rs.Commitments); err != nil {
		return fmt.Errorf("failed unmarshaling commitments: %v", err)
	}

	return nil

}

func (s *State) loadCommitments(rawCommitments []committee.Commitment) error {
	s.Commitments = nil

	for _, cmt := range rawCommitments {
		commitment := Commitment{
			From: int32(cmt.From),
		}

		serCommitments := &SerializedCommitment{}
		if err := serCommitments.FromBytes(cmt.Data); err != nil {
			return fmt.Errorf("failed unmarshaling serialized commitment: %v", err)
		}

		// Load commitments of current sender.
		for _, rawCmt := range serCommitments.Commitments {
			p := suite.Point() // Create an empty curve point
			// Assign it the commitment
			if err := p.UnmarshalBinary(rawCmt); err != nil {
				return fmt.Errorf("failed unmarshaling commitment (%s): %v", base64.StdEncoding.EncodeToString(rawCmt), err)
			}
			commitment.Commitments = append(commitment.Commitments, p)
		}

		// Load encryption shares of current sender.
		// We load *everyone's* shares even though we can only decrypt our own share.
		// This is done, so we will be able to persist everyone's shares into the block,
		// because the block can be replicated to other nodes and they need to to be able
		// to reconstruct the randomness at a later point.
		for _, rawEncShare := range serCommitments.EncShares {
			encShare := &EncShare{}
			if _, err := asn1.Unmarshal(rawEncShare, encShare); err != nil {
				return fmt.Errorf("failed unmarshaling raw encryption share")
			}
			p := suite.Point() // Create an empty curve point
			// Assign it to an encryption share
			if err := p.UnmarshalBinary(encShare.V); err != nil {
				return fmt.Errorf("failed unmarshaling encryption share (%s): %v", base64.StdEncoding.EncodeToString(encShare.V), err)
			}

			commitment.EncShares = append(commitment.EncShares, &pvss.PubVerShare{
				P: dleq.Proof{}, // We don't need to verify the proof, as it is checked during consensus.
				S: share.PubShare{
					I: encShare.I,
					V: p,
				},
			})
		}

		s.Commitments = append(s.Commitments, commitment)

	} // for

	return nil
}

func (s *State) ToBytes() []byte {
	panic("implement me")
}

type RawState struct {
	Commitments []committee.Commitment
}

type Commitment struct {
	From        int32
	EncShares   []*pvss.PubVerShare // n encrypted shares and corresponding ZKPs
	Commitments []kyber.Point       // f+1 commitments
}

func (cmt Commitment) ToRawForm(from uint32) (committee.Commitment, error) {
	var z committee.Commitment

	shares := cmt.EncShares
	commitments := cmt.Commitments

	proofs := Proof{}
	for _, encShare := range shares {
		proofs.Proofs = append(proofs.Proofs, encShare.P)
	}

	rawProofs, err := proofs.ToBytes()
	if err != nil {
		return z, fmt.Errorf("failed marshaling proofs: %v", err)
	}

	serializedCommitment := SerializedCommitment{}

	for _, encShare := range shares {
		index := encShare.S.I
		value, err := encShare.S.V.MarshalBinary()
		if err != nil {
			return z, fmt.Errorf("failed marshaling encryption share value: %v", err)
		}

		rawEncShare := EncShare{
			I: index,
			V: value,
		}

		rawEncShareBytes, err := asn1.Marshal(rawEncShare)
		if err != nil {
			return z, fmt.Errorf("failed marshaling raw encryption share: %v", err)
		}

		serializedCommitment.EncShares = append(serializedCommitment.EncShares, rawEncShareBytes)
	}

	for i := range commitments {
		commitment := commitments[i]

		commitmentBytes, err := commitment.MarshalBinary()
		if err != nil {
			return z, fmt.Errorf("failed marshaling commitment: %v", err)
		}

		serializedCommitment.Commitments = append(serializedCommitment.Commitments, commitmentBytes)
	}

	serializedCommitmentBytes, err := serializedCommitment.ToBytes()
	if err != nil {
		return z, fmt.Errorf("failed serializing commitment: %v", err)
	}

	return committee.Commitment{
		Data:  serializedCommitmentBytes,
		From:  from,
		Proof: rawProofs,
	}, nil
}

type SerializedCommitment struct {
	Commitments [][]byte
	EncShares   [][]byte
}

func (scm SerializedCommitment) ToBytes() ([]byte, error) {
	return asn1.Marshal(scm)
}

func (scm *SerializedCommitment) FromBytes(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, scm)
	return err
}

type EncShare struct {
	I int
	V []byte
}

type Proof struct {
	Proofs []dleq.Proof
}

func (p Proof) ToBytes() ([]byte, error) {

	sps := SerializedProofs{}

	for _, proof := range p.Proofs {

		r, err := proof.R.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed marshaling R in proof: %v", err)
		}

		vg, err := proof.VG.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed marshaling VG in proof: %v", err)
		}

		vh, err := proof.VH.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed marshaling VH in proof: %v", err)
		}

		sps.Proofs = append(sps.Proofs, SerializedProof{
			R:  r,
			VH: vh,
			VG: vg,
		})
	}
	return sps.ToBytes()
}

type SerializedProofs struct {
	Proofs []SerializedProof
}

func (sps SerializedProofs) ToBytes() ([]byte, error) {
	return asn1.Marshal(sps)
}

func (sps *SerializedProofs) Initialize(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, sps)
	return err
}

func (sp SerializedProof) ToBytes() ([]byte, error) {
	return asn1.Marshal(sp)
}

func (sp *SerializedProof) Initialize(bytes []byte) error {
	_, err := asn1.Unmarshal(bytes, sp)
	return err
}

type SerializedProof struct {
	R  []byte
	VG []byte
	VH []byte
}

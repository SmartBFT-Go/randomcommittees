package cs

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
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
	ourIndex int
	sk      kyber.Scalar
	pk      kyber.Point
	pubKeys []kyber.Point
	// State
	commitment          *Commitment
	commitmentInRawForm *committee.Commitment
	state *State
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

	// Locate our index within the nodes according to the ID and public keys
	cs.ourIndex, err = IsNodeInConfig(cs.id, pkRaw, nodes)
	if err != nil {
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
func IsNodeInConfig(id uint32, expectedPubKey []byte, nodes committee.Nodes) (int, error) {
	for i, node := range nodes {
		if node.ID != int32(id) {
			continue
		}
		if bytes.Equal(node.PubKey, expectedPubKey) {
			return i, nil
		}
		return 0, fmt.Errorf("expected public key %s but found %s",
			base64.StdEncoding.EncodeToString(expectedPubKey),
			base64.StdEncoding.EncodeToString(node.PubKey))
	}
	return 0, fmt.Errorf("could not find ID %d among %v", id, nodes)
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

	newState, isState := state.(*State)
	if ! isState {
		return feedback, nil, fmt.Errorf("expected to receive a committee.State state but got %v", reflect.TypeOf(state))
	}

	// This state is different than the one we have, so assign the updated state.
	if cs.state == nil || newState.header.BodyDigest != cs.state.header.BodyDigest {
		cs.state = newState
	}

	// Search for a commitment among the current state.
	// If we found a commitment in the current state, then load it to avoid computing it.
	commitments := cs.state.commitments
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

	var changed bool

	// If we have any commitments sent, refine them
	newCommitments, err := refineCommitments(input.Commitments)
	if err != nil {
		return feedback, nil, fmt.Errorf("failed extracting raw commitments from input: %v", err)
	}

	for i := 0; i < len(newCommitments) && len(cs.state.commitments) < cs.threshold(); i++ {
		changed = true
		cs.state.commitments = append(cs.state.commitments, newCommitments[i])
		cs.state.body.Commitments = append(cs.state.body.Commitments, input.Commitments[i])
	}


	// We check if the state has changed during this invocation
	if changed {
		cs.state.bodyBytes = cs.state.body.Bytes()
		cs.state.header.BodyDigest = digest(cs.state.bodyBytes)
	}

	// Always increment the header stats
	if cs.state.header.RemainingRounds > 0 {
		cs.state.header.RemainingRounds--
	}

	// Did we receive reconstruction shares?
	receivedReconShares := len(input.ReconShares) > 0

	// Is this the last round for this committee and we should send reconstruction shares?
	if len(cs.state.commitments) == cs.threshold() && cs.state.header.RemainingRounds == 0 && !receivedReconShares {
		reconShares, err := cs.createReconShares()
		if err != nil {
			return feedback, nil, fmt.Errorf("failed creating reconstruction shares: %v", err)
		}
		feedback.ReconShares = reconShares
	}

	if receivedReconShares {
		secret, err := cs.secretFromReconShares(input.ReconShares)
		if err != nil {
			return feedback, state, err
		}

		// TODO: pick the committee from the secret and assign it
		_ = secret
	}


	return feedback, state, nil

}

func (cs *CommitteeSelection) VerifyCommitment(commitment committee.Commitment, key committee.PublicKey) error {
	panic("implement me")
}

func (cs *CommitteeSelection) VerifyReconShare(share committee.ReconShare, key committee.PublicKey) error {
	panic("implement me")
}

func (cs *CommitteeSelection) secretFromReconShares(reconShares []committee.ReconShare) ([]byte, error) {
	var shares []*share.PubShare
	for _, reconShare := range reconShares {
		decShare, err := encShareToPubVerShare(reconShare.Data)
		if err != nil {
			return nil, fmt.Errorf("failed processing decryption share of %d: %v", reconShare.About, err)
		}
		shares = append(shares, &decShare.S)
	}

	t := cs.threshold()
	n := len(cs.pubKeys)

	secret, err := share.RecoverCommit(suite, shares, t, n)
	if err != nil {
		return nil, fmt.Errorf("failed reconstructing secret: %v", err)
	}

	secretAsBytes, err := secret.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling secret to bytes: %v", err)
	}

	return secretAsBytes, nil
}

func recoverSecret(decShares []*pvss.PubVerShare, t int, n int) (kyber.Point, error) {
	var shares []*share.PubShare
	for _, s := range decShares {
		shares = append(shares, &s.S)
	}
	return share.RecoverCommit(suite, shares, t, n)
}



func (cs *CommitteeSelection) createReconShares() ([]committee.ReconShare, error) {
	var res []committee.ReconShare
	for _, cmt := range cs.state.commitments {
		ourShare := cmt.EncShares[cs.ourIndex]
		decryptedShare, err := decShare(cs.sk, ourShare)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting our own share(%v): %v", ourShare, err)
		}

		reconShare, err := decShareToReconShare(uint32(cmt.From), decryptedShare)
		if err != nil {
			return nil, err
		}

		res = append(res, *reconShare)
	}

	return res, nil
}

func decShareToReconShare(from uint32, decryptedShare *pvss.PubVerShare) (*committee.ReconShare, error) {
	decShareBytes, err := decryptedShare.S.V.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed decrypting shares")
	}

	p := decryptedShare.P
	proof := Proof{
		Proofs: []dleq.Proof{
			{
				R: p.R,
				VG: p.VG,
				VH: p.VH,
			},
		},
	}

	proofBytes, err := proof.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling proof: %v", err)
	}

	// We use here the EncShare struct even though it is a decryption,
	// because their fields are equivalent.
	decShare := EncShare{
		I: decryptedShare.S.I,
		V: decShareBytes,
	}

	rawDecShare, err := asn1.Marshal(decShare)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling decryption share")
	}

	return &committee.ReconShare{
		Data: rawDecShare,
		Proof: proofBytes,
		About: from,
	}, nil
}

func decShare(x kyber.Scalar, encShare *pvss.PubVerShare) (*pvss.PubVerShare, error) {
	G := suite.Point().Base()
	decryptedV := suite.Point().Mul(suite.Scalar().Inv(x), encShare.S.V)
	share := &share.PubShare{I: encShare.S.I, V: decryptedV}
	P, _, _, err := dleq.NewDLEQProof(suite, G, decryptedV, x)
	if err != nil {
		return nil, fmt.Errorf("failed creating DLEQ proof: %v", err)
	}
	return &pvss.PubVerShare{S: *share,P: *P}, nil
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

func (cs *CommitteeSelection) threshold() int {
	pubKeys := cs.pubKeys
	n := len(pubKeys)
	f := (n - 1) / 3
	t := f + 1
	return t
}

func (cs *CommitteeSelection) commit() (shares []*pvss.PubVerShare, commitments []kyber.Point, err error) {
	pubKeys := cs.pubKeys

	secret := suite.Scalar().Pick(suite.RandomStream())

	shares, commit, err := pvss.EncShares(suite, h, pubKeys, secret, cs.threshold())
	if err != nil {
		return nil, nil, fmt.Errorf("failed computing encryption shares: %v", err)
	}

	_, commitments = commit.Info()

	return shares, commitments, nil
}

type State struct {
	commitments []Commitment
	header Header
	body   Body
	bodyBytes []byte
}

func (s *State) Initialize(rawState []byte) error {
	bb := bytes.NewBuffer(rawState)
	// Read header size
	headerSizeBuff := make([]byte, 4)
	if _, err := bb.Read(headerSizeBuff); err != nil {
		stateAsString := base64.StdEncoding.EncodeToString(rawState)
		return fmt.Errorf("failed reading header size from raw state (%s): %v", stateAsString, err)
	}
	headerSize := int(binary.BigEndian.Uint32(headerSizeBuff))
	headerBuff := make([]byte, headerSize)
	if _, err := bb.Read(headerBuff); err != nil {
		stateAsString := base64.StdEncoding.EncodeToString(rawState)
		return fmt.Errorf("failed reading header from raw state (%s): %v", stateAsString, err)
	}

	// Read header
	header := &Header{}
	if _, err := asn1.Unmarshal(headerBuff, header); err != nil {
		stateAsString := base64.StdEncoding.EncodeToString(rawState)
		return fmt.Errorf("failed reading header from raw state (%s): %v", stateAsString, err)
	}

	s.header = *header

	// If the digest of our previous state is equal to the digest of the next state,
	// then no need to process the body as the result would not change.
	if header.BodyDigest == s.header.BodyDigest {
		return nil
	}

	// The rest of the bytes are for the body
	remainingLength := len(rawState) - (headerSize + 4)
	bodyBuff := rawState[remainingLength:]

	body := &Body{}
	if _, err := asn1.Unmarshal(bodyBuff, body); err != nil {
		stateAsString := base64.StdEncoding.EncodeToString(rawState)
		return fmt.Errorf("failed unmarshaling state bytes(%s): %v", stateAsString, err)
	}

	if err := s.loadCommitments(body.Commitments); err != nil {
		return fmt.Errorf("failed unmarshaling commitments: %v", err)
	}

	s.bodyBytes = bodyBuff
	s.body = *body

	return nil

}

func (s *State) ToBytes() []byte {
	bb := bytes.Buffer{}
	headerBytes := s.header.Bytes()
	headerLength := len(headerBytes)
	headerLengthBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(headerLengthBuff, uint32(headerLength))
	bb.Write(headerLengthBuff)
	bb.Write(headerBytes)
	bb.Write(s.bodyBytes)
	return bb.Bytes()
}

func (s *State) loadCommitments(rawCommitments []committee.Commitment) error {
	var err error

	s.body.Commitments = rawCommitments
	s.commitments = nil
	s.commitments, err = refineCommitments(rawCommitments)

	return err
}

func encShareToPubVerShare(rawEncShare []byte) (*pvss.PubVerShare, error){
	encShare := &EncShare{}
	if _, err := asn1.Unmarshal(rawEncShare, encShare); err != nil {
		return nil, fmt.Errorf("failed unmarshaling raw encryption share")
	}
	p := suite.Point() // Create an empty curve point
	// Assign it to an encryption share
	if err := p.UnmarshalBinary(encShare.V); err != nil {
		return nil, fmt.Errorf("failed unmarshaling encryption share (%s): %v", base64.StdEncoding.EncodeToString(encShare.V), err)
	}

	return &pvss.PubVerShare{
		P: dleq.Proof{}, // We don't need to verify the proof, as it is checked during consensus.
		S: share.PubShare{
			I: encShare.I,
			V: p,
		},
	}, nil
}

func refineCommitments(rawCommitments []committee.Commitment) ([]Commitment, error){
	var result []Commitment

	for _, cmt := range rawCommitments {
		commitment := Commitment{
			From: int32(cmt.From),
		}

		serCommitments := &SerializedCommitment{}
		if err := serCommitments.FromBytes(cmt.Data); err != nil {
			return nil, fmt.Errorf("failed unmarshaling serialized commitment: %v", err)
		}

		// Load commitments of current sender.
		for _, rawCmt := range serCommitments.Commitments {
			p := suite.Point() // Create an empty curve point
			// Assign it the commitment
			if err := p.UnmarshalBinary(rawCmt); err != nil {
				return nil, fmt.Errorf("failed unmarshaling commitment (%s): %v", base64.StdEncoding.EncodeToString(rawCmt), err)
			}
			commitment.Commitments = append(commitment.Commitments, p)
		}

		// Load encryption shares of current sender.
		// We load *everyone's* shares even though we can only decrypt our own share.
		// This is done, so we will be able to persist everyone's shares into the block,
		// because the block can be replicated to other nodes and they need to to be able
		// to reconstruct the randomness at a later point.
		for _, rawEncShare := range serCommitments.EncShares {
			pubVerShare, err := encShareToPubVerShare(rawEncShare)
			if err != nil {
				return nil, err
			}
			commitment.EncShares = append(commitment.EncShares, pubVerShare)
		}

		result = append(result, commitment)
	} // for

	return result, nil

}

type Header struct {
	RemainingRounds int32
	CommitteeIncarnation int32
	BodyDigest string
}

func (h Header) Bytes() []byte {
	headerBytes, err := asn1.Marshal(h)
	if err != nil {
		panic(err)
	}
	return headerBytes
}

type Body struct {
	Commitments []committee.Commitment
	ReconShares []committee.ReconShare
}

func (b Body) Bytes() []byte {
	bodyBytes, err := asn1.Marshal(b)
	if err != nil {
		panic(err)
	}
	return bodyBytes
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

func digest(bytes []byte) string {
	h := sha256.New()
	h.Write(bytes)
	return hex.EncodeToString(h.Sum(nil))
}

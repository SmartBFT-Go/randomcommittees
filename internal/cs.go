/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cs

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"time"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

type CommitteeSelector func(config committee.Config, seed []byte) []int32

type CommitteeSelection struct {
	SelectCommittee CommitteeSelector
	Logger          committee.Logger
	// Configuration
	id        int32
	sk        kyber.Scalar
	pk        kyber.Point
	pubKeys   []kyber.Point
	ids2Index map[int32]int
	nodes     committee.Nodes
	// State
	commitment          *Commitment
	commitmentInRawForm *committee.Commitment
	state               *State
}

func (cs *CommitteeSelection) GenerateKeyPair(rand io.Reader) (committee.PublicKey, committee.PrivateKey, error) {
	sk := suite.Scalar().Pick(random.New(rand))
	pk := suite.Point().Mul(sk, h)
	pkRaw, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling public key: %v", err)
	}
	skRaw, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling private key: %v", err)
	}

	cs.Logger.Infof("Generated public key: %s", base64.StdEncoding.EncodeToString(pkRaw))

	return pkRaw, skRaw, nil
}

func (cs *CommitteeSelection) Initialize(ID int32, privateKey committee.PrivateKey, nodes committee.Nodes) error {
	if reflect.DeepEqual(cs.nodes, nodes) {
		cs.Logger.Debugf("Skipping initialization because nodes haven't changed")
		return nil
	}

	var sk kyber.Scalar

	if len(privateKey) == 0 {
		cs.Logger.Debugf("Initializing a non committee member instance")
	} else {
		sk = suite.Scalar()
		if err := sk.UnmarshalBinary(privateKey); err != nil {
			return fmt.Errorf("failed unmarshaling secret key: %v", err)
		}
	}

	cs.resetState()

	cs.nodes = nodes

	if len(privateKey) > 0 {
		cs.sk = sk
		cs.pk = suite.Point().Mul(cs.sk, h)
		cs.id = ID
	}

	cs.Logger.Infof("ID: %d, nodes: %s", ID, nodes)

	var nodeConfig []string
	for i, node := range nodes {
		cs.ids2Index[node.ID] = i
		nodeConfig = append(nodeConfig, fmt.Sprintf("%d --> %d", i, node.ID))
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

func (cs *CommitteeSelection) resetState() {
	cs.sk = nil
	cs.pk = nil
	cs.id = math.MaxInt32
	cs.ids2Index = make(map[int32]int)
	cs.pubKeys = nil
}

func (cs *CommitteeSelection) ourIndex() (int, bool) {
	// Locate our index within the nodes according to the ID and public keys
	for i, pk := range cs.pubKeys {
		if cs.pk != nil && cs.pk.Equal(pk) {
			cs.Logger.Debugf("Returning our index (%d) among %v", i, cs.nodes.IDs())
			return i, true
		}
	}

	return 0, false
}

// IsNodeInConfig returns whether the given node is in the config.
func IsNodeInConfig(id int32, expectedPubKey []byte, nodes committee.Nodes) (int, error) {
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
	if !isState {
		return feedback, nil, fmt.Errorf("expected to receive a committee.State state but got %v", reflect.TypeOf(state))
	}

	// This state is different than the one we have, so assign the updated state.
	if cs.state == nil || newState.header.BodyDigest != cs.state.header.BodyDigest {
		prevDigest := `""`
		if cs.state != nil {
			prevDigest = cs.state.header.BodyDigest
		} else {
		}
		cs.Logger.Infof("State we got differs from the state we have, updating it: %s --> %s", prevDigest, newState.header.BodyDigest)
		cs.Logger.Debugf("State we had: %s", cs.state)
		cs.Logger.Debugf("State we got: %s", newState)
		cs.state = newState
	}

	// Search for a commitment among the current state.
	// If we found a commitment in the current state, then load it to avoid computing it.
	commitments := cs.state.commitments
	if err := cs.loadOurCommitment(commitments); err != nil {
		return committee.Feedback{}, nil, err
	}

	// Prepare a fresh commitment if we haven't found one in the current committee, or didn't prepare one earlier.
	if cs.commitment == nil {
		if err := cs.prepareCommitment(); err != nil {
			return committee.Feedback{}, nil, err
		}
	}

	// Assign the commitment to be sent
	feedback.Commitment = cs.commitmentInRawForm

	var changed bool

	// If we have any commitments received, refine them
	cs.Logger.Infof("Received %d commitments in input", len(input.Commitments))
	newCommitments, err := refineCommitments(input.Commitments, false)
	if err != nil {
		return feedback, nil, fmt.Errorf("failed extracting raw commitments from input: %v", err)
	}

	if len(input.Commitments) > 0 {
		cs.Logger.Infof("Received %d commitments and refined %d commitments", len(input.Commitments), len(newCommitments))
	}

	for i := 0; i < len(newCommitments) && len(cs.state.commitments) < cs.threshold(); i++ {
		cs.Logger.Debugf("Added commitment from %d to state", newCommitments[i].From)
		changed = true
		cs.state.commitments = append(cs.state.commitments, newCommitments[i])
		cs.state.body.Commitments = append(cs.state.body.Commitments, input.Commitments[i])

		// If we persisted a commitment from ourselves, do not send any commitment in the feedback.
		if newCommitments[i].From == cs.id {
			feedback.Commitment = nil
		}
	}

	// We check if the state has changed during this invocation
	if changed {
		cs.state.bodyBytes = cs.state.body.Bytes()
		prevDigest := cs.state.header.BodyDigest
		cs.state.header.BodyDigest = digest(cs.state.bodyBytes)
		cs.Logger.Infof("State changed from %s to %s", prevDigest, cs.state.header.BodyDigest)
		state = cs.state
	}

	// Did we receive reconstruction shares?
	receivedReconShares := len(input.ReconShares) > 0

	cs.Logger.Debugf("State: %s", cs.state)

	// Is this the last round for this committee and we should send reconstruction shares?
	if len(cs.state.commitments) >= cs.threshold() && !receivedReconShares {
		reconShares, err := cs.createReconShares()
		if err != nil {
			return feedback, nil, fmt.Errorf("failed creating reconstruction shares: %v", err)
		}
		feedback.ReconShares = reconShares
	}

	if receivedReconShares {
		inputBeforeDeduplication := input.ReconShares
		input.ReconShares = deduplicateReconShares(input.ReconShares, cs.threshold())

		cs.Logger.Infof("Received %d ReconShares and de-duplicated into %d ReconShares",
			len(inputBeforeDeduplication), len(input.ReconShares))

		combinedSecret, err := cs.secretFromReconShares(input.ReconShares)
		if err != nil {
			return feedback, state, err
		}

		feedback.NextCommittee = cs.SelectCommittee(input.NextConfig, []byte(digest(combinedSecret)))
		cs.Logger.Infof("Next committee out of %v will be %v", input.NextConfig.Nodes.IDs(), feedback.NextCommittee)
	}
	return feedback, state, nil
}

func deduplicateReconShares(in []committee.ReconShare, threshold int) []committee.ReconShare {
	sender2about := make(map[int32]map[int32]struct{})
	for _, rcs := range in {
		about, exists := sender2about[rcs.From]
		if !exists {
			about = make(map[int32]struct{})
		}
		about[rcs.About] = struct{}{}
		sender2about[rcs.From] = about
	}

	// Remove mappings that have less than a threshold cardinality
	for sender, about := range sender2about {
		if len(about) < threshold {
			delete(sender2about, sender)
		}
	}

	// Remove mappings until we have exactly a threshold of cardinality
	for len(sender2about) > threshold {
		for sender := range sender2about {
			delete(sender2about, sender)
			break
		}
	}

	// Fold everything into the result slice, filtering out
	// ReconShares from nodes that didn't make the cut
	var res []committee.ReconShare
	for _, e := range in {
		_, exists := sender2about[e.From]
		if !exists {
			continue
		}
		res = append(res, e)
	}

	return res
}

func SelectCommittee(config committee.Config, seed []byte, size int) []int32 {
	r := rand.New(&randomness{seed: seed})
	rangeMapping := rangeMappingFromWeights(config.EffectiveWeights(), r)

	ids := randomIntList(config.Nodes.IDs())
	return ids.permute(rangeMapping).
		dePrioritize(config.ExcludedNodes).
		prioritize(config.MandatoryNodes)[:size]
}

type randomness struct {
	seed  []byte
	state []byte
}

func (r *randomness) Int63() int64 {
	if len(r.state) == 0 {
		r.state = sha256Hash(r.seed)
		r.seed = sha256Hash(r.seed)
	}
	defer func() {
		r.state = r.state[8:]
	}()
	n := int64(binary.BigEndian.Uint64(r.state[:8]))
	if n < 0 {
		n *= -1
	}
	return n
}

func (r *randomness) Seed(_ int64) {
	panic("this random source should not be seeded")
}

func (cs *CommitteeSelection) VerifyCommitment(commitment committee.Commitment) error {
	start := time.Now()
	defer func() {
		cs.Logger.Debugf("Commitment from %d took %s to verify", commitment.From, time.Since(start))
	}()

	cms, err := refineCommitments([]committee.Commitment{commitment}, true)

	if err != nil {
		return fmt.Errorf("failed refining commitments: %v", err)
	}

	if len(cms) != 1 {
		return fmt.Errorf("refining succeeded but got %d commitments instead of 1", len(cms))
	}

	cmt := cms[0]

	pvss := PVSS{
		Proofs:               cmt.Proofs,
		EncryptedEvaluations: cmt.EncShares,
		Commitments:          cmt.Commitments,
	}

	if err := pvss.VerifyCommit(cs.pubKeys); err != nil {
		return fmt.Errorf("commit from %d isn't sound: %v", cmt.From, err)
	}

	return nil
}

func (cs *CommitteeSelection) VerifyReconShare(share committee.ReconShare) error {
	start := time.Now()
	defer func() {
		cs.Logger.Debugf("ReconShare from %d about %d took %s to verify", share.From, share.About, time.Since(start))
	}()
	d := suite.Point()
	if err := d.UnmarshalBinary(share.Data); err != nil {
		return fmt.Errorf("failed unmarshaling reconshare: %v", err)
	}

	// Locate the encrypted share
	e, pk, err := cs.locateEncryptedShares(share.About, share.From)
	if err != nil {
		return err
	}

	proof := SerializedProof{}
	if err := proof.Initialize(share.Proof); err != nil {
		return fmt.Errorf("failed unmarshaling decryption proof: %v", err)
	}

	return VerifyDecShare(pk, d, e, proof)
}

func (cs *CommitteeSelection) secretFromReconShares(reconShares []committee.ReconShare) ([]byte, error) {
	reconstructedSecrets, err := reconstructSecrets(reconShares, cs.ids2Index)
	if err != nil {
		return nil, err
	}

	bb := bytes.Buffer{}

	for _, secret := range reconstructedSecrets {
		secretAsBytes, err := secret.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed marshaling secret to bytes: %v", err)
		}
		bb.Write(secretAsBytes)
	}

	return bb.Bytes(), nil
}

func reconstructSecrets(reconShares []committee.ReconShare, ids2Index map[int32]int) ([]kyber.Point, error) {
	// Index2Share is a mapping from scalar evaluation point to the value of a share
	committerId2SharesByIndex := make(map[int32]Index2Share)
	for _, reconShare := range reconShares {
		m, exists := committerId2SharesByIndex[reconShare.About]
		if !exists {
			m = make(map[int64]kyber.Point)
			committerId2SharesByIndex[reconShare.About] = m
		}

		decShare, err := refineReconShare(reconShare.Data)
		if err != nil {
			return nil, fmt.Errorf("failed processing decryption share of %d: %v", reconShare.About, err)
		}

		evalPoint, exists := ids2Index[reconShare.From]

		if !exists {
			return nil, fmt.Errorf("node %d doesn't exist", reconShare.From)
		}

		m[int64(evalPoint)] = decShare
	}

	committerIds2ReconstructedSecrets := make(Source2Points)
	for committerId, sharesByIndex := range committerId2SharesByIndex {
		reconstructedShare := ReconstructShare(sharesByIndex)
		committerIds2ReconstructedSecrets[committerId] = reconstructedShare
	}

	return committerIds2ReconstructedSecrets.SortedPoints(), nil
}

func (cs *CommitteeSelection) createReconShares() ([]committee.ReconShare, error) {
	ourIndex, weAreInCommittee := cs.ourIndex()
	if !weAreInCommittee {
		cs.Logger.Infof("We are not in the committee, should not send reconstruction shares")
		return nil, nil
	}
	cs.Logger.Infof("Total public keys: %v", len(cs.pubKeys))
	var res []committee.ReconShare
	for _, cmt := range cs.state.commitments {
		ourShare := cmt.EncShares[ourIndex]
		d, proof, err := DecryptShare(cs.pk, cs.sk, ourShare)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting our share: %v", err)
		}

		proofBytes, err := proof.ToBytes()
		if err != nil {
			return nil, err
		}

		dBytes, err := d.MarshalBinary()
		if err != nil {
			return nil, err
		}

		rs := committee.ReconShare{
			From:  cs.id,
			Proof: proofBytes,
			Data:  dBytes,
			About: cmt.From, // The committer ID
		}

		cs.Logger.Infof("Creating ReconShare corresponding to the commitment of %d", cmt.From)

		res = append(res, rs)
	}

	cs.Logger.Infof("Created %d ReconShares", len(res))

	return res, nil
}

func (cs *CommitteeSelection) loadOurCommitment(commitments []Commitment) error {
	for _, cmt := range commitments {
		if cs.id == cmt.From {
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
			cs.Logger.Infof("Found our commitment among %d commitments", len(commitments))
		}
	}

	cs.Logger.Infof("Our commitment wasn't found among %d commitments", len(commitments))
	return nil
}

func (cs *CommitteeSelection) prepareCommitment() error {
	pvss := PVSS{}
	if err := pvss.Commit(cs.threshold(), cs.pubKeys); err != nil {
		return err
	}

	commitment := Commitment{
		From:        cs.id,
		EncShares:   pvss.EncryptedEvaluations,
		Commitments: pvss.Commitments,
		Proofs:      pvss.Proofs,
	}

	rawCommitment, err := commitment.ToRawForm(cs.id)
	if err != nil {
		return fmt.Errorf("failed computing commitment: %v", err)
	}

	cs.commitment = &commitment
	cs.commitmentInRawForm = &rawCommitment

	cs.Logger.Infof("Prepared a commitment with %d commitments and %d encrypted shares",
		len(commitment.Commitments), len(commitment.EncShares))

	return nil
}

func (cs *CommitteeSelection) threshold() int {
	pubKeys := cs.pubKeys
	n := len(pubKeys)
	f := (n - 1) / 3
	t := f + 1
	return t
}

func commitmentOnPolynomialEvaluation(i int64, commitments []kyber.Point) kyber.Point {
	var points []kyber.Point
	for j, c := range commitments {
		e := Exp(suite.Scalar().SetInt64(i), j)
		p := suite.Point().Mul(e, c)
		points = append(points, p)
	}

	sum := points[0]
	points = points[1:]
	for _, p := range points {
		sum = suite.Point().Add(sum, p)
	}
	return sum
}

type State struct {
	commitments commitments
	header      Header
	body        Body
	bodyBytes   []byte
}

func (s *State) String() string {
	m := make(map[string]interface{})
	m["commitments"] = s.commitments.asStrings()
	m["header"] = fmt.Sprintf("BodyDigest: %s", s.header.BodyDigest)
	m["body"] = fmt.Sprintf("commitments: %d", len(s.body.Commitments))

	str, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}

	return string(str)
}

func (s *State) Initialize(rawState []byte) error {
	// Reset all state first
	*s = State{}

	if len(rawState) == 0 {
		return nil
	}

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

	// If the digest of our previous state is equal to the digest of the next state,
	// then no need to process the body as the result would not change.
	if header.BodyDigest == s.header.BodyDigest {
		return nil
	}

	s.header = *header

	// The rest of the bytes are for the body
	bodyBuff := rawState[headerSize+4:]

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
	if len(s.bodyBytes) == 0 {
		return nil
	}
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
	s.commitments, err = refineCommitments(rawCommitments, false)

	return err
}

func (cs *CommitteeSelection) locateEncryptedShares(committerID int32, decrypterID int32) (e, pk kyber.Point, err error) {
	// We search for the commitment in this committee according to the committer ID.
	for _, cmt := range cs.state.commitments {
		if cmt.From != committerID {
			continue
		}
		// Once we found the commitment, we need to search the appropriate encrypted share that
		// the committer has encrypted under that target node's public key.
		decrypterIndex, exists := cs.ids2Index[decrypterID]
		if !exists {
			return nil, nil, fmt.Errorf("%d is not a valid ID", decrypterID)
		}
		e = cmt.EncShares[decrypterIndex]
		pk = cs.pubKeys[decrypterIndex]
		return
	}
	return nil, nil, fmt.Errorf("commitment of %d wasn't found", committerID)
}

func refineReconShare(rawEncShare []byte) (kyber.Point, error) {
	p := suite.Point() // Create an empty curve point
	// Assign it to an encryption share
	if err := p.UnmarshalBinary(rawEncShare); err != nil {
		return nil, fmt.Errorf("failed unmarshaling encryption share (%s): %v", base64.StdEncoding.EncodeToString(rawEncShare), err)
	}
	return p, nil
}

func refineCommitments(rawCommitments []committee.Commitment, loadProofs bool) ([]Commitment, error) {
	var result []Commitment

	for _, cmt := range rawCommitments {
		commitment := Commitment{
			From: cmt.From,
		}

		if loadProofs {
			sps := SerializedProofs{}
			if err := sps.Initialize(cmt.Proof); err != nil {
				return nil, fmt.Errorf("failed parsing proofs for %d: %v", cmt.From, err)
			}

			commitment.Proofs = sps
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
			encShare := suite.Point()
			if err := encShare.UnmarshalBinary(rawEncShare); err != nil {
				return nil, fmt.Errorf("failed unmarshaling encryption share: %v", err)
			}
			commitment.EncShares = append(commitment.EncShares, encShare)
		}

		result = append(result, commitment)
	} // for

	return result, nil

}

type Header struct {
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
}

func (b Body) Bytes() []byte {
	bodyToSerialize := Body{}
	for _, cmt := range b.Commitments {
		bodyToSerialize.Commitments = append(bodyToSerialize.Commitments, committee.Commitment{
			Data: cmt.Data,
			From: cmt.From,
		})
	}

	bodyBytes, err := asn1.Marshal(bodyToSerialize)
	if err != nil {
		panic(err)
	}

	return bodyBytes
}

type commitments []Commitment

func (cms commitments) asStrings() []string {
	var res []string
	for _, cmt := range cms {
		res = append(res, fmt.Sprintf("from %d, %d commitments, %d shares, %d proofs",
			cmt.From, len(cmt.Commitments), len(cmt.EncShares), len(cmt.Proofs.Proofs)))
	}
	return res
}

type Commitment struct {
	From        int32
	EncShares   []kyber.Point // n encrypted shares
	Commitments []kyber.Point // f+1 commitments
	Proofs      SerializedProofs
}

func (cmt Commitment) ToRawForm(from int32) (committee.Commitment, error) {
	var z committee.Commitment

	serializedCommitment := SerializedCommitment{}

	for _, encShare := range cmt.EncShares {
		rawEncShareBytes, err := encShare.MarshalBinary()
		if err != nil {
			return z, fmt.Errorf("failed marshaling raw encryption share: %v", err)
		}

		serializedCommitment.EncShares = append(serializedCommitment.EncShares, rawEncShareBytes)
	}

	for _, commitment := range cmt.Commitments {
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

	rawProofs, err := cmt.Proofs.ToBytes()
	if err != nil {
		return z, fmt.Errorf("failed marshaling proofs: %v", err)
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

func digest(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(sha256Hash(bytes))
}

func sha256Hash(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}

type randomIntList []int32

func (l randomIntList) toSet() map[int32]struct{} {
	m := make(map[int32]struct{})
	for _, n := range l {
		m[n] = struct{}{}
	}

	return m
}

func (l randomIntList) without(list randomIntList) randomIntList {
	var res randomIntList
	s := list.toSet()
	for _, n := range l {
		if _, exists := s[n]; exists {
			continue
		}
		res = append(res, n)
	}
	return res
}

func (l randomIntList) permute(rm *rangeMapping) randomIntList {
	m := make(map[int32]struct{})

	var res randomIntList
	for len(res) < len(l) {

		n := rm.randomSample()
		if _, exists := m[n]; exists {
			continue
		}
		m[n] = struct{}{}
		res = append(res, n)
		rm.remove(n)
	}

	return res
}

func (l randomIntList) prioritize(prioritized randomIntList) randomIntList {
	var res randomIntList
	res = append(res, prioritized...)
	res = append(res, l.without(prioritized)...)
	return res
}

func (l randomIntList) dePrioritize(dePrioritized randomIntList) randomIntList {
	var res randomIntList
	res = append(res, l.without(dePrioritized)...)
	res = append(res, dePrioritized...)
	return res
}

// Source2Points defines curve points indexed by their source
type Source2Points map[int32]kyber.Point

// SortedShares returns the points sorted by their sources
func (c2s Source2Points) SortedPoints() []kyber.Point {
	var sources []int
	for source := range c2s {
		sources = append(sources, int(source))
	}

	sort.Ints(sources)

	var res []kyber.Point
	for _, source := range sources {
		p := c2s[int32(source)]
		res = append(res, p)
	}
	return res
}

func rangeMappingFromWeights(weights []committee.Weight, r *rand.Rand) *rangeMapping {
	var totalWeight int64
	for _, w := range weights {
		totalWeight += int64(w.Weight)
	}

	res := &rangeMapping{
		r:       r,
		m:       rangePairsFromWeights(weights, make(map[int32]struct{})),
		total:   totalWeight,
		weights: weights,
		removed: make(map[int32]struct{}),
	}
	return res
}

func rangePairsFromWeights(weights []committee.Weight, removed map[int32]struct{}) map[int32]rangePair {
	m := make(map[int32]rangePair)

	var cumulativeWeights int64
	for _, w := range weights {
		if _, exists := removed[w.ID]; exists {
			continue
		}
		m[w.ID] = rangePair{
			weight: w.Weight,
			a:      cumulativeWeights,
			b:      cumulativeWeights + int64(w.Weight),
		}
		cumulativeWeights += int64(w.Weight)
	}

	return m
}

type rangeMapping struct {
	total   int64
	r       *rand.Rand
	m       map[int32]rangePair
	removed map[int32]struct{}
	weights []committee.Weight
}

type rangePair struct {
	a, b   int64
	weight int32
}

func (rm *rangeMapping) randomSample() int32 {
	sample := int64(rm.r.Intn(int(rm.total)))
	for id, ab := range rm.m {
		if sample >= ab.a && sample < ab.b {
			return id
		}
	}

	panic(fmt.Sprintf("%d is not within [0, %d)", sample, rm.total))
}

func (rm *rangeMapping) remove(n int32) {
	rm.removed[n] = struct{}{}
	w := rm.m[n].weight
	rm.total -= int64(w)
	rm.m = rangePairsFromWeights(rm.weights, rm.removed)
}

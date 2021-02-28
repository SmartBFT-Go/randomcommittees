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
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"reflect"
	"sort"

	committee "github.com/SmartBFT-Go/randomcommittees/pkg"
	"go.dedis.ch/kyber/v3"
)

type CommitteeSelection struct {
	// Configuration
	id        uint32
	ourIndex  int
	sk        kyber.Scalar
	pk        kyber.Point
	pubKeys   []kyber.Point
	ids2Index map[int32]int
	// State
	commitment          *Commitment
	commitmentInRawForm *committee.Commitment
	state               *State
}

func (cs *CommitteeSelection) GenerateKeyPair(rand io.Reader) ([]byte, []byte, error) {
	sk := suite.Scalar().Pick(suite.RandomStream())
	pk := suite.Point().Mul(sk, h)
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

	cs.ids2Index = make(map[int32]int)
	for i, node := range nodes {
		cs.ids2Index[node.ID] = i
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
	if !isState {
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
		combinedSecret, err := cs.secretFromReconShares(input.ReconShares)
		if err != nil {
			return feedback, state, err
		}

		feedback.NextCommittee = SelectCommittee(input.NextConfig, []byte(digest(combinedSecret)))
	}
	return feedback, state, nil

}

func SelectCommittee(config committee.Config, seed []byte) []uint32 {
	failureChance := big.NewRat(1, config.InverseFailureChance)
	expectedCommitteeSize := CommitteeSize(int64(len(config.Nodes)), config.FailedTotalNodesPercentage, *failureChance)

	ids := randomIntList(weightedList(config.Weights))
	return ids.permute(seed).distinctPrefixOfSize(expectedCommitteeSize)
}

func mapToSlice(m map[uint32]struct{}) []uint32 {
	var res []uint32
	for k := range m {
		res = append(res, k)
	}
	return res
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
	return int64(binary.BigEndian.Uint64(r.state[:8]))
}

func (r *randomness) Seed(_ int64) {
	panic("this random source should not be seeded")
}

func (cs *CommitteeSelection) VerifyCommitment(commitment committee.Commitment) error {
	cms, err := refineCommitments([]committee.Commitment{commitment})
	if err != nil {
		return fmt.Errorf("failed refining commitments: %v", err)
	}

	if len(cms) != 1 {
		return fmt.Errorf("refining succeeded but got %d commitments instead of 1", len(cms))
	}

	for _, cmt := range cms {
		pvss := PVSS{
			Proofs:               cmt.Proofs,
			EncryptedEvaluations: cmt.EncShares,
			Commitments:          cmt.Commitments,
		}

		if err := pvss.VerifyCommit(cs.pubKeys); err != nil {
			return fmt.Errorf("commit from %d isn't sound: %v", cmt.From, err)
		}
	}

	return nil
}

func (cs *CommitteeSelection) VerifyReconShare(share committee.ReconShare) error {
	d := suite.Point()
	if err := d.UnmarshalBinary(share.Data); err != nil {
		return fmt.Errorf("failed unmarshaling reconshare: %v", err)
	}

	// Locate the encrypted share
	e, pk, err := cs.locateEncryptedShares(share.About, int32(share.From))
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
	reconstructedSecrets, err := reconstructSecrets(reconShares)
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

func reconstructSecrets(reconShares []committee.ReconShare) ([]kyber.Point, error) {
	// Index2Share is a mapping from scalar evaluation point to the value of a share
	committerId2SharesByIndex := make(map[uint32]Index2Share)
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

		m[int64(reconShare.From)] = decShare
	}

	committerIds2ReconstructedSecrets := make(Source2Points)
	for committerId, sharesByIndex := range committerId2SharesByIndex {
		reconstructedShare := ReconstructShare(sharesByIndex)
		committerIds2ReconstructedSecrets[committerId] = reconstructedShare
	}

	return committerIds2ReconstructedSecrets.SortedPoints(), nil
}

func (cs *CommitteeSelection) createReconShares() ([]committee.ReconShare, error) {
	var res []committee.ReconShare
	for _, cmt := range cs.state.commitments {
		ourShare := cmt.EncShares[cs.ourIndex]
		d, proof, err := DecryptShare(cs.sk, ourShare)
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
			Proof: proofBytes,
			Data:  dBytes,
			About: uint32(cmt.From), // The committer ID
		}

		res = append(res, rs)
	}

	return res, nil
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
	pvss := PVSS{}
	if err := pvss.Commit(cs.threshold(), cs.pubKeys); err != nil {
		return err
	}

	commitment := Commitment{
		From:        int32(cs.id),
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

	return nil
}

func (cs *CommitteeSelection) threshold() int {
	pubKeys := cs.pubKeys
	n := len(pubKeys)
	f := (n - 1) / 3
	t := f + 1
	return t
}

func commitmentOnPolynomialEvaluation(i *big.Int, commitments []kyber.Point) kyber.Point {
	var points []kyber.Point
	for j, c := range commitments {
		exp := big.NewInt(0).Exp(i, big.NewInt(int64(j)), nil)
		e := suite.Scalar().SetInt64(exp.Int64())
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
	commitments []Commitment
	header      Header
	body        Body
	bodyBytes   []byte
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

func (cs *CommitteeSelection) locateEncryptedShares(committerID uint32, targetID int32) (e, pk kyber.Point, err error) {
	// We search for the commitment in this committee according to the committer ID.
	for _, cmt := range cs.state.commitments {
		if cmt.From != int32(committerID) {
			continue
		}
		// Once we found the commitment, we need to search the appropriate encrypted share that
		// the committer has encrypted under that target node's public key.
		target, exists := cs.ids2Index[targetID]
		if !exists {
			return nil, nil, fmt.Errorf("%d is not a valid ID", targetID)
		}
		e = cmt.EncShares[target]
		pk = cs.pubKeys[target]
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

func refineCommitments(rawCommitments []committee.Commitment) ([]Commitment, error) {
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
	RemainingRounds      int32
	CommitteeIncarnation int32
	BodyDigest           string
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

type ReconShare struct {
	D    kyber.Point
	From int64
}

type Commitment struct {
	From        int32
	EncShares   []kyber.Point // n encrypted shares and corresponding ZKPs
	Commitments []kyber.Point // f+1 commitments
	Proofs      SerializedProofs
}

func (cmt Commitment) ToRawForm(from uint32) (committee.Commitment, error) {
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
	return hex.EncodeToString(sha256Hash(bytes))
}

func sha256Hash(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}

func weightedList(wl []committee.Weight) []uint32 {
	res := make(randomIntList, 0)
	for _, weight := range wl {
		for i := 0; i < int(weight.Weight); i++ {
			res = append(res, uint32(weight.ID))
		}
	}
	return res
}

type randomIntList []uint32

func (l randomIntList) permute(seed []byte) randomIntList {
	if l == nil {
		return nil
	}
	var permutedIDs randomIntList
	r := rand.New(&randomness{seed: seed})
	for _, index := range r.Perm(len(l)) {
		permutedIDs = append(permutedIDs, l[index])
	}
	return permutedIDs
}

func (l randomIntList) distinctPrefixOfSize(size int) randomIntList {
	res := make(map[uint32]struct{})
	for _, id := range l {
		if len(res) == size {
			break
		}
		res[id] = struct{}{}
	}
	return mapToSlice(res)
}

// Source2Points defines curve points indexed by their source
type Source2Points map[uint32]kyber.Point

// SortedShares returns the points sorted by their sources
func (c2s Source2Points) SortedPoints() []kyber.Point {
	var sources []int
	for source := range c2s {
		sources = append(sources, int(source))
	}

	sort.Ints(sources)

	var res []kyber.Point
	for _, source := range sources {
		p := c2s[uint32(source)]
		res = append(res, p)
	}
	return res
}

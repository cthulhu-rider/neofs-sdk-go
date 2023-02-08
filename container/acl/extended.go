package acl

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/version"
)

type Extended struct {
	m acl.Table
}

func NewExtended(rule Rule) (e Extended) {
	var mv refs.Version

	v := version.Current()
	v.WriteToV2(&mv)

	e.m.SetVersion(&mv)
	e.m.SetRecords([]acl.Record{rule.m})
	return
}

// reads Extended from acl.Table message. If checkFieldPresence is set,
// returns an error on absence of any protocol-required field. Verifies format
// of any presented field according to NeoFS API V2 protocol.
func (x *Extended) readFromV2(m acl.Table, checkFieldPresence bool) error {
	var err error

	if checkFieldPresence && m.GetVersion() == nil {
		return errors.New("missing version")
	}

	if mCnr := m.GetContainerID(); mCnr != nil {
		var cnr cid.ID

		err := cnr.ReadFromV2(*mCnr)
		if err != nil {
			return fmt.Errorf("invalid container ID: %w", err)
		}
	}

	rs := m.GetRecords()
	if checkFieldPresence && len(rs) == 0 {
		return errors.New("missing rules")
	}

	for i := range rs {
		err = verifyRule(rs[i], checkFieldPresence)
		if err != nil {
			return fmt.Errorf("invalid rule #%d", i)
		}
	}

	x.m = m

	return nil
}

// ReadFromV2 reads Extended from the acl.Table message. Checks if the
// message conforms to NeoFS API V2 protocol.
//
// See also WriteToV2.
func (x *Extended) ReadFromV2(m acl.Table) error {
	return x.readFromV2(m, true)
}

// WriteToV2 writes Extended to the acl.Table message. The message MUST NOT
// be nil.
//
// See also ReadFromV2.
func (x Extended) WriteToV2(m *acl.Table) {
	*m = x.m
}

// Marshal encodes Extended into a binary format of the NeoFS API protocol
// (Protocol Buffers with direct field order).
//
// See also Unmarshal.
func (x Extended) Marshal() []byte {
	var m acl.Table
	x.WriteToV2(&m)

	return m.StableMarshal(nil)
}

// Unmarshal decodes NeoFS API protocol binary format into the Extended
// (Protocol Buffers with direct field order). Returns an error describing a
// format violation.
//
// See also Marshal.
func (x *Extended) Unmarshal(data []byte) error {
	var m acl.Table

	err := m.Unmarshal(data)
	if err != nil {
		return err
	}

	return x.readFromV2(m, false)
}

// MarshalJSON encodes Extended into a JSON format of the NeoFS API protocol
// (Protocol Buffers JSON).
//
// See also UnmarshalJSON.
func (x Extended) MarshalJSON() ([]byte, error) {
	var m acl.Table
	x.WriteToV2(&m)

	return m.MarshalJSON()
}

// UnmarshalJSON decodes NeoFS API protocol JSON format into the Extended
// (Protocol Buffers JSON). Returns an error describing a format violation.
//
// See also MarshalJSON.
func (x *Extended) UnmarshalJSON(data []byte) error {
	var m acl.Table

	err := m.UnmarshalJSON(data)
	if err != nil {
		return err
	}

	return x.readFromV2(m, false)
}

// CID returns identifier of the container that should use given access control rules.
func (x Extended) Container() (cid.ID, bool) {
	var cnr cid.ID

	mCnr := x.m.GetContainerID()
	if mCnr == nil {
		return cnr, false
	}

	if err := cnr.ReadFromV2(*mCnr); err != nil {
		panic(fmt.Sprintf("unexpected decoding error: %v", err))
	}

	return cnr, true
}

// SetCID sets identifier of the container that should use given access control rules.
func (x *Extended) RestrictToContainer(cnr cid.ID) {
	var mCnr refs.ContainerID
	cnr.WriteToV2(&mCnr)

	x.m.SetContainerID(&mCnr)
}

func (x *Extended) AddRule(rule Rule) {
	x.m.SetRecords(append(x.m.GetRecords(), rule.m))
}

func (x *Extended) SetFirstRule(rule Rule) {
	x.m.SetRecords(append([]acl.Record{rule.m}, x.m.GetRecords()...))
}

type RequestMetadata struct {
	requestHeaders, objectHeaders []Header
}

func (x *RequestMetadata) SetObjectHeaders(hs []Header) {
	x.objectHeaders = hs
}

func (x *RequestMetadata) SetRequestHeaders(hs []Header) {
	x.requestHeaders = hs
}

var (
	ErrAccessDenied = errors.New("access denied")
	ErrRuleNotFound = errors.New("rule not found")
)

func (x Extended) CheckAccess(senderKey neofscrypto.PublicKey, senderRole Role, op Op, meta RequestMetadata) error {
	if senderKey == nil {
		panic("missing sender key")
	}

	bKey := neofscrypto.SerializePublicKey(senderKey)
	rs := x.m.GetRecords()

	for i := range rs {
		// check type of operation
		if rs[i].GetOperation() != castOp(op) {
			continue
		}

		// check target subject
		subjectMatches := false
		ts := rs[i].GetTargets()

	targetsLoop:
		for j := range ts {
			ks := ts[j].GetKeys()
			if len(ks) == 0 {
				if subjectMatches = ts[j].GetRole() == castRole(senderRole); subjectMatches {
					break
				}

				continue
			}

			for k := range ks {
				if subjectMatches = bytes.Equal(ks[k], bKey); subjectMatches {
					break targetsLoop
				}
			}
		}

		if !subjectMatches {
			continue
		}

		// check headers
		headersMatched := 0
		fs := rs[i].GetFilters()

	filterLoop:
		for j := range fs {
			var hs []Header

			switch fs[j].GetHeaderType() {
			default:
				return fmt.Errorf("unsupported header type %v (rule#%d, filter#%d)", fs[j].GetHeaderType(), i, j)
			case acl.HeaderTypeRequest:
				hs = meta.requestHeaders
			case acl.HeaderTypeObject:
				hs = meta.objectHeaders
			case acl.HeaderTypeService:
				break filterLoop
			}

			ruleHeaderKey := fs[j].GetKey()
			ruleHeaderValue := fs[j].GetValue()
			var match func(ruleHeader, requestHeader string) bool

			switch fs[j].GetMatchType() {
			default:
				return fmt.Errorf("unsupported matcher %v (rule#%d, filter#%d)", fs[j].GetMatchType(), i, j)
			case acl.MatchTypeStringEqual:
				match = func(ruleHeader, requestHeader string) bool { return ruleHeader == requestHeader }
			case acl.MatchTypeStringNotEqual:
				match = func(ruleHeader, requestHeader string) bool { return ruleHeader != requestHeader }
			}

			for k := range hs {
				if hs[k].key != ruleHeaderKey {
					continue
				}

				if match(ruleHeaderValue, hs[k].val) {
					headersMatched++
					break
				}
			}
		}

		if headersMatched >= len(fs) {
			switch rs[i].GetAction() {
			default:
				return fmt.Errorf("rule #%d matches, but action is not supported %v", i, rs[i].GetAction())
			case acl.ActionAllow:
				return nil
			case acl.ActionDeny:
				return ErrAccessDenied
			}
		}
	}

	return ErrRuleNotFound
}

// Record of the ContainerExtendedACL rule, that defines ContainerExtendedACL action, targets for this action,
// object service operation and filters for request headers.
//
// Record is compatible with v2 acl.EACLRecord message.
type Rule struct {
	m acl.Record
}

// reads Extended from acl.Table message. If checkFieldPresence is set,
// returns an error on absence of any protocol-required field. Verifies format
// of any presented field according to NeoFS API V2 protocol.
func verifyRule(m acl.Record, checkFieldPresence bool) error {
	ts := m.GetTargets()
	if checkFieldPresence && len(ts) == 0 {
		return errors.New("missing target subjects")
	}

	for i := range ts {
		role := ts[i].GetRole()
		ks := ts[i].GetKeys()

		if checkFieldPresence && role == 0 && len(ks) == 0 {
			return fmt.Errorf("empty target #%d", i)
		}

		if role != 0 && len(ks) > 0 {
			return fmt.Errorf("role is set to %v along with key list in target #%d", role, i)
		}

		for j := range ks {
			if len(ks[j]) == 0 {
				return fmt.Errorf("public key #%d is empty in target #%d", j, i)
			}
		}
	}

	fs := m.GetFilters()
	for i := range fs {
		if checkFieldPresence && fs[i].GetKey() == "" {
			return fmt.Errorf("missing key in filter #%d", i)
		}

		if checkFieldPresence && fs[i].GetValue() == "" {
			return fmt.Errorf("missing value in filter #%d", i)
		}
	}

	return nil
}

func checkTarget(t RuleTarget) {
	if t.role == 0 && len(t.keys) == 0 {
		panic("uninitialized rule target")
	}
}

func newRule(action acl.Action, target RuleTarget, op Op) (r Rule) {
	checkTarget(target)

	if op == 0 {
		panic("uninitialized operation")
	}

	r.m.SetOperation(castOp(op))
	r.m.SetAction(action)
	r.AddTargetSubjects(target)

	return

}

func Allow(op Op, target RuleTarget) Rule {
	return newRule(acl.ActionAllow, target, op)
}

func Deny(op Op, target RuleTarget) Rule {
	return newRule(acl.ActionDeny, target, op)
}

func (x *Rule) AddTargetSubjects(ts ...RuleTarget) {
nextTarget:
	for i := range ts {
		checkTarget(ts[i])

		if ts[i].role > 0 {
			var r2 acl.Role
			switch ts[i].role {
			default:
				panic(fmt.Sprintf("unsupported role %v", ts[i].role))
			case RoleOwner:
				r2 = acl.RoleUser
			case RoleContainer, RoleInnerRing:
				r2 = acl.RoleSystem
			case RoleOthers:
				r2 = acl.RoleOthers
			}

			var t acl.Target
			t.SetRole(r2)

			x.m.SetTargets(append(x.m.GetTargets(), t))

			continue
		}

		mts := x.m.GetTargets()
		for j := range mts {
			if mts[j].GetRole() == 0 {
				mts[j].SetKeys(append(mts[j].GetKeys(), ts[i].keys...))
				continue nextTarget
			}
		}

		var t acl.Target
		t.SetKeys(ts[i].keys)

		x.m.SetTargets(append(x.m.GetTargets(), t))
	}
}

func (x *Rule) FilterBy(fs ...Filter) {
	mfs := make([]acl.HeaderFilter, len(fs))
	for i := range fs {
		if fs[i] == (Filter{}) {
			panic(fmt.Sprintf("uninitialized filter #%d", i))
		}

		mfs[i] = fs[i].m
	}

	x.m.SetFilters(mfs)
}

type RuleTarget struct {
	role Role
	keys [][]byte
}

func SubjectsWithKeys(keys []neofscrypto.PublicKey) RuleTarget {
	if len(keys) == 0 {
		panic("missing key list")
	}

	bKeys := make([][]byte, len(keys))

	for i := range keys {
		if keys[i] == nil {
			panic(fmt.Sprintf("nil key in list"))
		}

		bKeys[i] = neofscrypto.SerializePublicKey(keys[i])
	}

	return RuleTarget{keys: bKeys}
}

func SubjectsWithRole(role Role) RuleTarget {
	if role <= roleZero || role >= roleLast {
		panic(fmt.Sprintf("unsupported role %v", role))
	}
	return RuleTarget{role: role}
}

// Filter defines check conditions if request header is matched or not. Matched
// header means that request should be processed according to ContainerExtendedACL action.
//
// Filter is compatible with v2 acl.EACLRecord.Filter message.
type Filter struct {
	m acl.HeaderFilter
}

type Matcher = func(*Filter)

func MatchEquals(f *Filter) {
	f.m.SetMatchType(acl.MatchTypeStringEqual)
}

func MatchNotEquals(f *Filter) {
	f.m.SetMatchType(acl.MatchTypeStringNotEqual)
}

func newFilter(typ acl.HeaderType, m Matcher, h Header) (f Filter) {
	if m == nil {
		panic("nil matcher")
	}

	f.m.SetHeaderType(typ)
	f.m.SetKey(h.key)
	f.m.SetValue(h.val)
	m(&f)

	return
}

type Header struct {
	key, val string
}

func NewHeader(key, value string) Header {
	return Header{key, value}
}

func MatchRequestHeader(m Matcher, h Header) Filter {
	return newFilter(acl.HeaderTypeRequest, m, h)
}

func MatchObjectHeader(m Matcher, h Header) Filter {
	return newFilter(acl.HeaderTypeObject, m, h)
}

func ObjectIDHeader(id oid.ID) Header {
	return NewHeader(acl.FilterObjectID, id.EncodeToString())
}

func ByObjectID(id oid.ID) Filter {
	return MatchObjectHeader(MatchEquals, ObjectIDHeader(id))
}

func ExcludeObjectID(id oid.ID) Filter {
	return MatchObjectHeader(MatchNotEquals, ObjectIDHeader(id))
}

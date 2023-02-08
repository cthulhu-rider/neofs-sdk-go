package acl_test

import (
	"fmt"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	acl2 "github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	containertest "github.com/nspcc-dev/neofs-sdk-go/container/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	oidtest "github.com/nspcc-dev/neofs-sdk-go/object/id/test"
	"github.com/stretchr/testify/require"
)

const (
	fixedOp = acl.OpObjectGet
	otherOp = fixedOp + 1

	fixedRole = acl.RoleOwner
	otherRole = fixedRole + 1
)

var fixedKey = randomKey()

func randomKey() neofscrypto.PublicKey {
	k, err := keys.NewPrivateKey()
	if err != nil {
		panic(fmt.Errorf("generate random private key: %v", err))
	}

	return (*neofsecdsa.PublicKey)(&k.PrivateKey.PublicKey)
}

type checkResult int

const (
	checkFailed checkResult = iota
	checkAllowed
	checkDenied
	checkNoRule
)

func noRequestMeta(*acl.RequestMetadata) {}

func checkAccess(t testing.TB, expected checkResult, eACL acl.Extended, senderKey neofscrypto.PublicKey, senderRole acl.Role, op acl.Op, fMeta func(metadata *acl.RequestMetadata)) {
	var meta acl.RequestMetadata
	fMeta(&meta)

	err := eACL.CheckAccess(senderKey, senderRole, op, meta)

	switch expected {
	default:
		panic(fmt.Sprintf("invalid result enum value %v", expected))
	case checkFailed:
		require.NotErrorIs(t, err, acl.ErrRuleNotFound)
		require.NotErrorIs(t, err, acl.ErrAccessDenied)
		require.Error(t, err)
	case checkAllowed:
		require.NoError(t, err)
	case checkDenied:
		require.ErrorIs(t, err, acl.ErrAccessDenied)
	case checkNoRule:
		require.ErrorIs(t, err, acl.ErrRuleNotFound)
	}
}

func TestExtended_CheckAccess(t *testing.T) {
	t.Run("single rule", func(t *testing.T) {
		e := acl.NewExtended(acl.Deny(fixedOp, acl.SubjectsWithRole(fixedRole)))
		checkAccess(t, checkDenied, e, randomKey(), fixedRole, fixedOp, noRequestMeta)

		e = acl.NewExtended(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))
		checkAccess(t, checkAllowed, e, randomKey(), fixedRole, fixedOp, noRequestMeta)

		e = acl.NewExtended(acl.Deny(fixedOp, acl.SubjectsWithKeys([]neofscrypto.PublicKey{fixedKey})))
		checkAccess(t, checkDenied, e, fixedKey, otherRole, fixedOp, noRequestMeta)
	})

	t.Run("additional rules", func(t *testing.T) {
		e := acl.NewExtended(acl.Deny(fixedOp, acl.SubjectsWithRole(fixedRole)))
		checkAccess(t, checkDenied, e, fixedKey, fixedRole, fixedOp, noRequestMeta)

		e.AddRule(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))
		checkAccess(t, checkDenied, e, fixedKey, fixedRole, fixedOp, noRequestMeta)

		e.SetFirstRule(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))
		checkAccess(t, checkAllowed, e, fixedKey, fixedRole, fixedOp, noRequestMeta)
	})

	t.Run("additional targets", func(t *testing.T) {
		rule := acl.Deny(fixedOp, acl.SubjectsWithRole(fixedRole))
		e := acl.NewExtended(rule)

		checkAccess(t, checkNoRule, e, fixedKey, otherRole, fixedOp, noRequestMeta)

		rule.AddTargetSubjects(acl.SubjectsWithKeys([]neofscrypto.PublicKey{fixedKey}))
		e.AddRule(rule)

		checkAccess(t, checkDenied, e, fixedKey, otherRole, fixedOp, noRequestMeta)
	})

	t.Run("header filters", func(t *testing.T) {
		const (
			fixedReqHdrKey = "req_key"
			otherReqHdrKey = fixedReqHdrKey + "_other"
			fixedReqHdrVal = "req_val"
			otherReqHdrVal = fixedReqHdrVal + "_other"
			fixedObjHdrKey = "obj_key"
			otherObjHdrKey = fixedObjHdrKey + "_other"
			fixedObjHdrVal = "obj_val"
			otherObjHdrVal = fixedObjHdrVal + "_other"
		)

		rule := acl.Deny(fixedOp, acl.SubjectsWithRole(fixedRole))
		rule.FilterBy(acl.MatchRequestHeader(acl.MatchEquals, acl.NewHeader(fixedReqHdrKey, fixedReqHdrVal)))
		rule.FilterBy(acl.MatchObjectHeader(acl.MatchNotEquals, acl.NewHeader(fixedObjHdrKey, fixedObjHdrVal)))

		e := acl.NewExtended(rule)

		checkAccess(t, checkNoRule, e, fixedKey, fixedRole, fixedOp, noRequestMeta)

		for _, hs := range [][4]string{
			{fixedReqHdrKey, fixedReqHdrVal, fixedObjHdrKey, fixedObjHdrVal},
			{fixedReqHdrKey, fixedReqHdrVal, otherObjHdrKey, fixedObjHdrVal},
			{fixedReqHdrKey, otherReqHdrVal, fixedObjHdrKey, fixedObjHdrVal},
			{otherReqHdrKey, fixedReqHdrVal, fixedObjHdrKey, fixedObjHdrVal},
		} {
			checkAccess(t, checkNoRule, e, fixedKey, fixedRole, fixedOp, func(meta *acl.RequestMetadata) {
				meta.SetRequestHeaders([]acl.Header{acl.NewHeader(hs[0], hs[1])})
				meta.SetObjectHeaders([]acl.Header{acl.NewHeader(hs[2], hs[3])})
			})
		}

		checkAccess(t, checkDenied, e, fixedKey, fixedRole, fixedOp, func(meta *acl.RequestMetadata) {
			meta.SetRequestHeaders([]acl.Header{acl.NewHeader(fixedReqHdrKey, fixedReqHdrVal)})
			meta.SetObjectHeaders([]acl.Header{acl.NewHeader(fixedObjHdrKey, otherObjHdrVal)})
		})
	})

	t.Run("other subject/operation", func(t *testing.T) {
		e := acl.NewExtended(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))

		checkAccess(t, checkNoRule, e, randomKey(), fixedRole, otherOp, noRequestMeta)
		checkAccess(t, checkNoRule, e, randomKey(), otherRole, fixedOp, noRequestMeta)
	})

	t.Run("unsupported", func(t *testing.T) {
		t.Run("action", func(t *testing.T) {
			e := acl.NewExtended(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))

			// we "hack" this way because obviously library prevents unsupported things by design
			var me acl2.Table
			e.WriteToV2(&me)

			me.GetRecords()[0].SetAction(0)

			require.NoError(t, e.ReadFromV2(me))

			checkAccess(t, checkFailed, e, fixedKey, fixedRole, fixedOp, func(meta *acl.RequestMetadata) {
				meta.SetRequestHeaders([]acl.Header{acl.NewHeader("key", "value")})
			})
		})

		t.Run("matcher", func(t *testing.T) {
			rule := acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole))
			rule.FilterBy(acl.MatchRequestHeader(acl.MatchEquals, acl.NewHeader("key", "value")))

			e := acl.NewExtended(rule)

			// we "hack" this way because obviously library prevents unsupported things by design
			var me acl2.Table
			e.WriteToV2(&me)

			me.GetRecords()[0].GetFilters()[0].SetMatchType(0)

			require.NoError(t, e.ReadFromV2(me))

			checkAccess(t, checkFailed, e, fixedKey, fixedRole, fixedOp, func(meta *acl.RequestMetadata) {
				meta.SetRequestHeaders([]acl.Header{acl.NewHeader("key", "value")})
			})
		})

		t.Run("header type", func(t *testing.T) {
			rule := acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole))
			rule.FilterBy(acl.MatchRequestHeader(acl.MatchEquals, acl.NewHeader("key", "value")))

			e := acl.NewExtended(rule)

			// we "hack" this way because obviously library prevents unsupported things by design
			var me acl2.Table
			e.WriteToV2(&me)

			me.GetRecords()[0].GetFilters()[0].SetHeaderType(0)

			require.NoError(t, e.ReadFromV2(me))

			checkAccess(t, checkFailed, e, fixedKey, fixedRole, fixedOp, func(meta *acl.RequestMetadata) {
				meta.SetRequestHeaders([]acl.Header{acl.NewHeader("key", "value")})
			})
		})
	})
}

func TestExtendedEncoding(t *testing.T) {
	e := containertest.ExtendedACL()

	b := e.Marshal()

	var e2 acl.Extended
	require.NoError(t, e2.Unmarshal(b))
	require.Equal(t, e, e2)

	b, err := e.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, e2.UnmarshalJSON(b))
	require.Equal(t, e, e2)
}

func TestByObjectID(t *testing.T) {
	id := oidtest.ID()

	rule := acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole))
	rule.FilterBy(acl.ByObjectID(id))

	e := acl.NewExtended(rule)

	setObjectIDInRequest := func(id oid.ID) func(metadata *acl.RequestMetadata) {
		return func(meta *acl.RequestMetadata) {
			meta.SetObjectHeaders([]acl.Header{acl.ObjectIDHeader(id)})
		}
	}

	checkAccess(t, checkAllowed, e, fixedKey, fixedRole, fixedOp, setObjectIDInRequest(id))

	id2 := oidtest.ID()

	checkAccess(t, checkNoRule, e, fixedKey, fixedRole, fixedOp, setObjectIDInRequest(id2))

	rule = acl.Deny(fixedOp, acl.SubjectsWithRole(fixedRole))
	rule.FilterBy(acl.ExcludeObjectID(id))

	e.SetFirstRule(rule)

	checkAccess(t, checkDenied, e, fixedKey, fixedRole, fixedOp, setObjectIDInRequest(id2))
}

func TestExtended_RestrictToContainer(t *testing.T) {
	e := acl.NewExtended(acl.Allow(fixedOp, acl.SubjectsWithRole(fixedRole)))

	cnr, ok := e.Container()
	require.False(t, ok)

	cnr = cidtest.ID()

	e.RestrictToContainer(cnr)

	cnr, ok = e.Container()
	require.True(t, ok)
}

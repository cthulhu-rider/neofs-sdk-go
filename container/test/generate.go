package containertest

import (
	"math/rand"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	netmaptest "github.com/nspcc-dev/neofs-sdk-go/netmap/test"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
)

// Container returns random container.Container.
func Container() (x container.Container) {
	owner := usertest.ID()

	x.Init()
	x.SetAttribute("some attribute", "value")
	x.SetOwner(*owner)
	x.SetBasicACL(BasicACL())
	x.SetPlacementPolicy(netmaptest.PlacementPolicy())

	return x
}

// SizeEstimation returns random container.SizeEstimation.
func SizeEstimation() (x container.SizeEstimation) {
	x.SetContainer(cidtest.ID())
	x.SetEpoch(rand.Uint64())
	x.SetValue(rand.Uint64())

	return x
}

// BasicACL returns random acl.Basic.
func BasicACL() (x acl.Basic) {
	x.FromBits(rand.Uint32())
	return
}

func randomKey() neofscrypto.PublicKey {
	k, err := keys.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	return (*neofsecdsa.PublicKey)(&k.PrivateKey.PublicKey)
}

// ExtendedACL returns random acl.Extended.
func ExtendedACL() acl.Extended {
	rule := acl.Allow(acl.OpObjectGet, acl.SubjectsWithRole(acl.RoleOwner))
	rule.AddTargetSubjects(
		acl.SubjectsWithRole(acl.RoleContainer),
		acl.SubjectsWithKeys([]neofscrypto.PublicKey{randomKey(), randomKey()}),
	)
	rule.FilterBy(
		acl.MatchObjectHeader(acl.MatchEquals, acl.NewHeader("obj_key", "obj_value")),
		acl.MatchRequestHeader(acl.MatchNotEquals, acl.NewHeader("req_key", "req_value")),
	)

	e := acl.NewExtended(rule)
	e.RestrictToContainer(cidtest.ID())
	e.AddRule(acl.Deny(acl.OpObjectPut, acl.SubjectsWithRole(acl.RoleOthers)))

	return e
}

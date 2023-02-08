package bearertest

import (
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	containertest "github.com/nspcc-dev/neofs-sdk-go/container/test"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
)

// Token returns random bearer.Token.
//
// Resulting token is unsigned.
func Token() (t bearer.Token) {
	t.SetExp(3)
	t.SetNbf(2)
	t.SetIat(1)
	t.ForUser(*usertest.ID())
	t.SetExtendedACL(containertest.ExtendedACL())

	return t
}

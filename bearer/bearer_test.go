package bearer_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	v2acl "github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	bearertest "github.com/nspcc-dev/neofs-sdk-go/bearer/test"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	containertest "github.com/nspcc-dev/neofs-sdk-go/container/test"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/stretchr/testify/require"
)

// compares binary representations of two acl.Extended instances.
func compareExtendedACL(t1, t2 acl.Extended) bool {
	return bytes.Equal(t1.Marshal(), t2.Marshal())
}

func TestToken_SetExtendedACL(t *testing.T) {
	var val bearer.Token
	var m v2acl.BearerToken
	filled := bearertest.Token()

	val.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	val2 := filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))
	require.Zero(t, val2.ExtendedACL())

	val2 = filled

	jd, err := val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))
	require.Zero(t, val2.ExtendedACL())

	// set value

	eACL := containertest.ExtendedACL()

	val.SetExtendedACL(eACL)
	require.True(t, compareExtendedACL(eACL, val.ExtendedACL()))

	val.WriteToV2(&m)

	var eaclTableV2 v2acl.Table
	eACL.WriteToV2(&eaclTableV2)
	require.Equal(t, &eaclTableV2, m.GetBody().GetEACL())

	val2 = filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))
	require.True(t, compareExtendedACL(eACL, val.ExtendedACL()))

	val2 = filled

	jd, err = val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))
	require.True(t, compareExtendedACL(eACL, val.ExtendedACL()))
}

func TestToken_ForUser(t *testing.T) {
	var val bearer.Token
	var m v2acl.BearerToken
	filled := bearertest.Token()

	val.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	val2 := filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))

	val2.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	val2 = filled

	jd, err := val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))

	val2.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	// set value
	usr := *usertest.ID()

	var usrV2 refs.OwnerID
	usr.WriteToV2(&usrV2)

	val.ForUser(usr)

	val.WriteToV2(&m)
	require.Equal(t, usrV2, *m.GetBody().GetOwnerID())

	val2 = filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))

	val2.WriteToV2(&m)
	require.Equal(t, usrV2, *m.GetBody().GetOwnerID())

	val2 = filled

	jd, err = val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))

	val2.WriteToV2(&m)
	require.Equal(t, usrV2, *m.GetBody().GetOwnerID())
}

func testLifetimeClaim(t *testing.T, setter func(*bearer.Token, uint64), getter func(*v2acl.BearerToken) uint64) {
	var val bearer.Token
	var m v2acl.BearerToken
	filled := bearertest.Token()

	val.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	val2 := filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))

	val2.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	val2 = filled

	jd, err := val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))

	val2.WriteToV2(&m)
	require.Zero(t, m.GetBody())

	// set value
	exp := rand.Uint64()

	setter(&val, exp)

	val.WriteToV2(&m)
	require.Equal(t, exp, getter(&m))

	val2 = filled

	require.NoError(t, val2.Unmarshal(val.Marshal()))

	val2.WriteToV2(&m)
	require.Equal(t, exp, getter(&m))

	val2 = filled

	jd, err = val.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, val2.UnmarshalJSON(jd))

	val2.WriteToV2(&m)
	require.Equal(t, exp, getter(&m))
}

func TestToken_SetLifetime(t *testing.T) {
	t.Run("iat", func(t *testing.T) {
		testLifetimeClaim(t, (*bearer.Token).SetIat, func(token *v2acl.BearerToken) uint64 {
			return token.GetBody().GetLifetime().GetIat()
		})
	})

	t.Run("nbf", func(t *testing.T) {
		testLifetimeClaim(t, (*bearer.Token).SetNbf, func(token *v2acl.BearerToken) uint64 {
			return token.GetBody().GetLifetime().GetNbf()
		})
	})

	t.Run("exp", func(t *testing.T) {
		testLifetimeClaim(t, (*bearer.Token).SetExp, func(token *v2acl.BearerToken) uint64 {
			return token.GetBody().GetLifetime().GetExp()
		})
	})
}

func TestToken_InvalidAt(t *testing.T) {
	var val bearer.Token

	require.True(t, val.InvalidAt(0))
	require.True(t, val.InvalidAt(1))

	val.SetIat(1)
	val.SetNbf(2)
	val.SetExp(4)

	require.True(t, val.InvalidAt(0))
	require.True(t, val.InvalidAt(1))
	require.False(t, val.InvalidAt(2))
	require.False(t, val.InvalidAt(3))
	require.False(t, val.InvalidAt(4))
	require.True(t, val.InvalidAt(5))
}

func TestToken_AssertContainer(t *testing.T) {
	var val bearer.Token
	cnr := cidtest.ID()

	require.True(t, val.AssertContainer(cnr))

	eACL := containertest.ExtendedACL()

	eACL.RestrictToContainer(cidtest.ID())
	val.SetExtendedACL(eACL)
	require.False(t, val.AssertContainer(cnr))

	eACL.RestrictToContainer(cnr)
	val.SetExtendedACL(eACL)
	require.True(t, val.AssertContainer(cnr))
}

func TestToken_AssertUser(t *testing.T) {
	var val bearer.Token
	usr := *usertest.ID()

	require.True(t, val.AssertUser(usr))

	val.ForUser(*usertest.ID())
	require.False(t, val.AssertUser(usr))

	val.ForUser(usr)
	require.True(t, val.AssertUser(usr))
}

func TestToken_Sign(t *testing.T) {
	var val bearer.Token

	require.False(t, val.VerifySignature())

	k, err := keys.NewPrivateKey()
	require.NoError(t, err)

	key := k.PrivateKey
	val = bearertest.Token()

	require.NoError(t, val.Sign(key))

	require.True(t, val.VerifySignature())

	var m v2acl.BearerToken
	val.WriteToV2(&m)

	require.NotZero(t, m.GetSignature().GetKey())
	require.NotZero(t, m.GetSignature().GetSign())

	val2 := bearertest.Token()

	require.NoError(t, val2.Unmarshal(val.Marshal()))
	require.True(t, val2.VerifySignature())

	jd, err := val.MarshalJSON()
	require.NoError(t, err)

	val2 = bearertest.Token()
	require.NoError(t, val2.UnmarshalJSON(jd))
	require.True(t, val2.VerifySignature())
}

func TestToken_ReadFromV2(t *testing.T) {
	var val bearer.Token
	var m v2acl.BearerToken

	require.Error(t, val.ReadFromV2(m))

	var body v2acl.BearerTokenBody
	m.SetBody(&body)

	require.Error(t, val.ReadFromV2(m))

	var eACL v2acl.Table
	containertest.ExtendedACL().WriteToV2(&eACL)
	body.SetEACL(&eACL)

	require.Error(t, val.ReadFromV2(m))

	var lifetime v2acl.TokenLifetime
	body.SetLifetime(&lifetime)

	require.Error(t, val.ReadFromV2(m))

	const iat, nbf, exp = 1, 2, 3
	lifetime.SetIat(iat)
	lifetime.SetNbf(nbf)
	lifetime.SetExp(exp)

	body.SetLifetime(&lifetime)

	require.Error(t, val.ReadFromV2(m))

	var sig refs.Signature
	m.SetSignature(&sig)

	require.NoError(t, val.ReadFromV2(m))

	var m2 v2acl.BearerToken

	val.WriteToV2(&m2)
	require.Equal(t, m, m2)

	usr, usr2 := *usertest.ID(), *usertest.ID()

	require.True(t, val.AssertUser(usr))
	require.True(t, val.AssertUser(usr2))

	var usrV2 refs.OwnerID
	usr.WriteToV2(&usrV2)

	body.SetOwnerID(&usrV2)

	require.NoError(t, val.ReadFromV2(m))

	val.WriteToV2(&m2)
	require.Equal(t, m, m2)

	require.True(t, val.AssertUser(usr))
	require.False(t, val.AssertUser(usr2))

	k, err := keys.NewPrivateKey()
	require.NoError(t, err)

	signer := neofsecdsa.Signer(k.PrivateKey)

	var s neofscrypto.Signature

	require.NoError(t, s.Calculate(signer, body.StableMarshal(nil)))

	s.WriteToV2(&sig)

	require.NoError(t, val.ReadFromV2(m))
	require.True(t, val.VerifySignature())
	require.Equal(t, sig.GetKey(), val.SigningKeyBytes())
}

func TestResolveIssuer(t *testing.T) {
	k, err := keys.NewPrivateKey()
	require.NoError(t, err)

	var val bearer.Token

	require.Zero(t, bearer.ResolveIssuer(val))

	var m v2acl.BearerToken

	var sig refs.Signature
	sig.SetKey([]byte("invalid key"))

	m.SetSignature(&sig)

	require.NoError(t, val.Unmarshal(m.StableMarshal(nil)))

	require.Zero(t, bearer.ResolveIssuer(val))

	require.NoError(t, val.Sign(k.PrivateKey))

	var usr user.ID
	user.IDFromKey(&usr, k.PrivateKey.PublicKey)

	require.Equal(t, usr, bearer.ResolveIssuer(val))
}

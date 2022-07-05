package object_test

import (
	"math/rand"
	"testing"

	v2object "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	v2session "github.com/nspcc-dev/neofs-api-go/v2/session"
	cidtest "github.com/nspcc-dev/neofs-sdk-go/container/id/test"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	objecttest "github.com/nspcc-dev/neofs-sdk-go/object/test"
	sessiontest "github.com/nspcc-dev/neofs-sdk-go/session/test"
	usertest "github.com/nspcc-dev/neofs-sdk-go/user/test"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"github.com/stretchr/testify/require"
)

func TestInitCreation(t *testing.T) {
	var o object.Object
	cnr := cidtest.ID()
	own := *usertest.ID()

	object.InitCreation(&o, object.RequiredFields{
		Container: cnr,
		Owner:     own,
	})

	require.Equal(t, cnr, o.Container())
	require.Equal(t, own, o.Owner())
}

func TestObject_Init(t *testing.T) {
	val := objecttest.Object()

	val.Init()

	var msg v2object.Object
	val.WriteToV2(&msg)

	verV2 := msg.GetHeader().GetVersion()
	require.NotNil(t, verV2)

	var ver version.Version
	ver.ReadFromV2(*verV2)

	require.Equal(t, version.Current(), ver)

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

func TestObject_Container(t *testing.T) {
	var val object.Object

	require.Zero(t, val.Container())

	val = objecttest.Object()

	cnr := cidtest.ID()

	val.SetContainer(cnr)

	var msg v2object.Object
	val.WriteToV2(&msg)

	var msgCnr refs.ContainerID
	cnr.WriteToV2(&msgCnr)

	require.Equal(t, &msgCnr, msg.GetHeader().GetContainerID())

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

func TestObject_Owner(t *testing.T) {
	var val object.Object

	require.Zero(t, val.Owner())

	val = objecttest.Object()

	owner := *usertest.ID()

	val.SetOwner(owner)

	var msg v2object.Object
	val.WriteToV2(&msg)

	var msgOwner refs.OwnerID
	owner.WriteToV2(&msgOwner)

	require.Equal(t, &msgOwner, msg.GetHeader().GetOwnerID())

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

func TestObject_PayloadSize(t *testing.T) {
	var val object.Object

	require.Zero(t, val.PayloadSize())

	val = objecttest.Object()

	sz := rand.Uint64()

	val.SetPayloadSize(sz)

	var msg v2object.Object
	val.WriteToV2(&msg)

	require.Equal(t, sz, msg.GetHeader().GetPayloadLength())

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

func TestObject_CreatedAt(t *testing.T) {
	var val object.Object

	require.Zero(t, val.CreatedAt())

	val = objecttest.Object()

	epoch := rand.Uint64()

	val.SetCreationEpoch(epoch)

	var msg v2object.Object
	val.WriteToV2(&msg)

	require.Equal(t, epoch, msg.GetHeader().GetCreationEpoch())

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

func TestObject_Session(t *testing.T) {
	var val object.Object

	require.Zero(t, val.Session())

	val = objecttest.Object()

	s := *sessiontest.ObjectSigned()

	val.MakeSession(s)

	var msgSession v2session.Token
	s.WriteToV2(&msgSession)

	var msg v2object.Object
	val.WriteToV2(&msg)

	require.Equal(t, &msgSession, msg.GetHeader().GetSessionToken())

	var val2 object.Object
	require.NoError(t, val2.ReadFromV2(msg))

	require.Equal(t, val, val2)
}

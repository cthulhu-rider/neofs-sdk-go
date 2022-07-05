package object

import (
	"errors"
	"fmt"

	v2object "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// TODO: check docs
// Lock represents record with locked objects. It is compatible with
// NeoFS API V2 protocol.
//
// Lock instance can be written to the Object, see WriteLock/ReadLock.
type Lock struct {
	members []oid.ID
}

// TODO: check docs
// WriteLock writes Lock to the Object, and sets its type to TypeLock.
// The object must not be nil.
//
// See also ReadLock.
func (x *Object) WriteLock(l Lock) {
	if len(l.Members()) == 0 {
		panic("missing members")
	}

	x.hdr.SetObjectType(v2object.TypeLock)
	x.payload = l.Marshal()
	x.hdr.SetPayloadLength(uint64(len(x.payload)))
}

// TODO: add docs
func (x Object) IsLock() bool {
	return x.hdr.GetObjectType() == v2object.TypeLock
}

// TODO: check docs
// ReadLock reads Lock from the Object. The lock must not be nil.
// Returns an error describing incorrect format. Makes sense only
// if object has TypeLock type.
//
// See also WriteLock.
func (x Object) ReadLock(l *Lock) error {
	err := l.Unmarshal(x.payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	return nil
}

// TODO: check docs
// Marshal encodes the Lock into a NeoFS protocol binary format.
func (x Lock) Marshal() []byte {
	members := make([]refs.ObjectID, len(x.members))

	for i := range x.members {
		x.members[i].WriteToV2(&members[i])
	}

	var m v2object.Lock
	m.SetMembers(members)

	return m.StableMarshal(nil)
}

// TODO: check docs
// Unmarshal decodes the Lock from its NeoFS protocol binary representation.
func (x *Lock) Unmarshal(data []byte) error {
	var m v2object.Lock

	err := m.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("decode binary: %w", err)
	}

	num := m.NumberOfMembers()
	if num == 0 {
		return errors.New("missing members")
	}

	var id oid.ID
	x.members = make([]oid.ID, 0, num)
	mMembers := make(map[oid.ID]struct{}, num)

	m.IterateMembers(func(idV2 refs.ObjectID) {
		if err == nil {
			err = id.ReadFromV2(idV2)
			if err == nil {
				_, exists := mMembers[id]
				if exists {
					err = fmt.Errorf("duplicated member %s", id)
					return
				}

				mMembers[id] = struct{}{}
			}
		}
	})

	if err != nil {
		return fmt.Errorf("invalid member: %w", err)
	}

	return nil
}

// TODO: check docs
// WriteMembers writes list of locked members.
func (x *Lock) AppendMember(member oid.ID) {
	x.members = append(x.members, member)
}

// TODO: check docs
// ReadMembers reads list of locked members.
//
// Buffer length must not be less than NumberOfMembers.
func (x Lock) Members() []oid.ID {
	return x.members
}

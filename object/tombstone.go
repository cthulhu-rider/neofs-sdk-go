package object

import (
	"errors"
	"fmt"

	v2object "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-api-go/v2/tombstone"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// TODO: add docs
type Tombstone struct {
	members []oid.ID
}

// TODO: add docs
func (x *Object) WriteTombstone(t Tombstone) {
	if len(t.Members()) == 0 {
		panic("missing members")
	}

	x.hdr.SetObjectType(v2object.TypeTombstone)
	x.payload = t.Marshal()
	x.hdr.SetPayloadLength(uint64(len(x.payload)))
}

// TODO: add docs
func (x Object) IsTombstone() bool {
	return x.hdr.GetObjectType() == v2object.TypeTombstone
}

// TODO: add docs
func (x Object) ReadTombstone(t *Tombstone) error {
	err := t.Unmarshal(x.payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	return nil
}

// TODO: check docs
func (x Tombstone) Marshal() []byte {
	members := make([]refs.ObjectID, len(x.members))

	for i := range x.members {
		x.members[i].WriteToV2(&members[i])
	}

	var m tombstone.Tombstone
	m.SetMembers(members)

	return m.StableMarshal(nil)
}

// TODO: add docs
func (x *Tombstone) Unmarshal(data []byte) error {
	var m tombstone.Tombstone

	err := m.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("decode binary: %w", err)
	}

	members := m.GetMembers()
	if len(members) == 0 {
		return errors.New("missing members")
	}

	x.members = make([]oid.ID, len(members))
	mMembers := make(map[oid.ID]struct{}, len(members))
	var exists bool

	for i := range members {
		err = x.members[i].ReadFromV2(members[i])
		if err != nil {
			return fmt.Errorf("invalid member: %w", err)
		}

		_, exists = mMembers[x.members[i]]
		if exists {
			return fmt.Errorf("duplicated member %s", x.members[i])
		}

		mMembers[x.members[i]] = struct{}{}
	}

	if err != nil {
		return fmt.Errorf("invalid member: %w", err)
	}

	return nil
}

// TODO: check docs
func (x *Tombstone) AppendMember(member oid.ID) {
	x.members = append(x.members, member)
}

// TODO: check docs
func (x Tombstone) Members() []oid.ID {
	return x.members
}

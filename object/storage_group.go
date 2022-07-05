package object

import (
	"bytes"
	"errors"
	"fmt"
	"hash"

	v2object "github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	"github.com/nspcc-dev/neofs-api-go/v2/storagegroup"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/tzhash/tz"
)

// TODO: add docs
type StorageGroup struct {
	size uint64

	hash []byte

	members []oid.ID
}

// TODO: add docs
func (x *Object) WriteStorageGroup(sg StorageGroup) {
	if len(sg.Members()) == 0 {
		panic("missing members")
	}

	x.hdr.SetObjectType(v2object.TypeTombstone)
	x.payload = sg.Marshal()
	x.hdr.SetPayloadLength(uint64(len(x.payload)))
}

// TODO: add docs
func (x Object) IsStorageGroup() bool {
	return x.hdr.GetObjectType() == v2object.TypeStorageGroup
}

// TODO: add docs
func (x Object) ReadStorageGroup(sg *StorageGroup) error {
	err := sg.Unmarshal(x.payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	return nil
}

// TODO: add docs
func (x StorageGroup) Marshal() []byte {
	members := make([]refs.ObjectID, len(x.members))

	for i := range x.members {
		x.members[i].WriteToV2(&members[i])
	}

	var cs refs.Checksum
	cs.SetType(refs.TillichZemor)
	cs.SetSum(x.hash)

	var m storagegroup.StorageGroup
	m.SetValidationHash(&cs)
	m.SetValidationDataSize(x.size)
	m.SetMembers(members)

	return m.StableMarshal(nil)
}

// TODO: check docs
// Unmarshal unmarshals protobuf binary representation of StorageGroup.
//
// See also Marshal.
func (x *StorageGroup) Unmarshal(data []byte) error {
	var m storagegroup.StorageGroup

	err := m.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("decode storage group: %w", err)
	}

	cs := m.GetValidationHash()
	if len(cs.GetSum()) == 0 {
		return errors.New("missing group hash")
	}

	if cs.GetType() != refs.TillichZemor {
		return fmt.Errorf("invalid checksum type %v", cs.GetType())
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

	x.size = m.GetValidationDataSize()
	x.hash = cs.GetSum()

	return nil
}

// TODO: add docs
func (x *StorageGroup) AppendMember(member oid.ID) {
	x.members = append(x.members, member)
}

// TODO: add docs
func (x StorageGroup) Members() []oid.ID {
	return x.members
}

// TODO: check docs
// SetValidationDataSize sets total size of the payloads
// of objects in the storage group.
//
// See also ValidationDataSize.
func (x *StorageGroup) SetSize(sz uint64) {
	x.size = sz
}

// TODO: check docs
// ValidationDataSize returns total size of the payloads of objects in the storage group.
//
// Zero StorageGroup has 0 data size.
//
// See also SetValidationDataSize.
func (x StorageGroup) Size() uint64 {
	return x.size
}

// TODO: add docs
type StorageGroupChecksum struct {
	hash.Hash
}

// TODO: add docs
func (x *StorageGroupChecksum) Init() {
	x.Hash = tz.New()
}

// TODO: add docs
// SetValidationDataHash sets homomorphic hash from the
// concatenation of the payloads of the storage group members.
//
// See also ValidationDataHash.
func (x *StorageGroup) SetChecksum(cs StorageGroupChecksum) {
	x.hash = cs.Sum(nil)
}

// TODO: check docs
// ValidationDataHash returns homomorphic hash from the
// concatenation of the payloads of the storage group members
// and bool that indicates checksum presence in the storage
// group.
//
// Zero StorageGroup does not have validation data checksum.
//
// See also SetValidationDataHash.
func (x StorageGroup) AssertChecksum(cs StorageGroupChecksum) bool {
	return bytes.Equal(x.hash, cs.Sum(nil))
}

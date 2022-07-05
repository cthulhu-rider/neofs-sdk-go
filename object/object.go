package object

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"

	"github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	v2session "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-sdk-go/checksum"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/version"
	"github.com/nspcc-dev/tzhash/tz"
)

// TODO: upd Object type docs

// Object represents in-memory structure of the NeoFS object.
// Type is compatible with NeoFS API V2 protocol.
//
// Instance can be created depending on scenario:
//   * InitCreation (an object to be placed in container);
//   * New (blank instance, usually needed for decoding);
//   * NewFromV2 (when working under NeoFS API V2 protocol).
type Object struct {
	id oid.ID

	hdr object.Header

	sig neofscrypto.Signature

	payload []byte
}

// TODO: check docs
// reads Object from the object.Object message. If checkFieldPresence is set,
// returns an error on absence of any protocol-required field.
func (x *Object) readFromV2(m object.Object, checkFieldPresence bool) error {
	var err error

	mID := m.GetObjectID()
	if mID != nil {
		err = x.id.ReadFromV2(*mID)
		if err != nil {
			return fmt.Errorf("invalid ID: %w", err)
		}
	}

	hdr := m.GetHeader()
	if hdr != nil {
		mVer := hdr.GetVersion()
		if mVer != nil {
			err = new(version.Version).ReadFromV2(*mVer)
			if err != nil {
				return fmt.Errorf("invalid version: %w", err)
			}
		}

		mCnr := hdr.GetContainerID()
		if mCnr != nil {
			err = new(cid.ID).ReadFromV2(*mCnr)
			if err != nil {
				return fmt.Errorf("invalid container: %w", err)
			}
		} else if checkFieldPresence {
			return errors.New("missing container")
		}

		mOwner := hdr.GetOwnerID()
		if mOwner != nil {
			var owner user.ID

			err = owner.ReadFromV2(*mOwner)
			if err != nil {
				return fmt.Errorf("invalid owner: %w", err)
			}
		} else if checkFieldPresence {
			return errors.New("missing owner")
		}

		mPayloadChecksum := hdr.GetPayloadHash()
		if mPayloadChecksum != nil {
			err = new(checksum.Checksum).ReadFromV2(*mPayloadChecksum)
			if err != nil {
				return fmt.Errorf("invalid payload checksum: %w", err)
			}
		}

		switch hdr.GetObjectType() {
		default:
			return fmt.Errorf("unsupported type %v", hdr.GetObjectType())
		case
			object.TypeRegular,
			object.TypeTombstone,
			object.TypeStorageGroup,
			object.TypeLock:
		}

		mPayloadChecksum = hdr.GetHomomorphicHash()
		if mPayloadChecksum != nil {
			err = new(checksum.Checksum).ReadFromV2(*mPayloadChecksum)
			if err != nil {
				return fmt.Errorf("invalid payload homomorphic checksum: %w", err)
			}
		}

		mSession := hdr.GetSessionToken()
		if mSession != nil {
			var s session.Object

			err = s.ReadFromV2(*mSession)
			if err != nil {
				return fmt.Errorf("invalid session: %w", err)
			}
		}

		attrs := hdr.GetAttributes()
		mAttr := make(map[string]struct{}, len(attrs))
		var key, val string
		var was bool
		var withTickEpoch, withTickTopic bool

		for i := range attrs {
			key = attrs[i].GetKey()
			if key == "" {
				return errors.New("empty attribute key")
			}

			_, was = mAttr[key]
			if was {
				return fmt.Errorf("duplicated attribute %s", key)
			}

			val = attrs[i].GetValue()
			if val == "" {
				return fmt.Errorf("empty attribute value %s", key)
			}

			switch key {
			case object.SysAttributeExpEpoch:
				_, err = strconv.ParseUint(val, 10, 64)
			case object.SysAttributeTickEpoch:
				withTickEpoch = true
				_, err = strconv.ParseUint(val, 10, 64)
			case object.SysAttributeTickTopic:
				withTickTopic = true
			case attributeTimestamp:
				_, err = strconv.ParseInt(val, 10, 64)
			}

			if err != nil {
				return fmt.Errorf("invalid attribute value %s: %s (%w)", key, val, err)
			}

			mAttr[key] = struct{}{}
		}

		if withTickTopic && !withTickEpoch {
			return errors.New("notification topic without epoch attribute")
		}

		mSplit := hdr.GetSplit()
		if mSplit != nil {
			mPrev := mSplit.GetPrevious()
			if mPrev != nil {
				err = new(oid.ID).ReadFromV2(*mPrev)
				if err != nil {
					return fmt.Errorf("invalid ID of the previous object: %w", err)
				}
			}

			children := mSplit.GetChildren()
			mChildren := make(map[oid.ID]struct{}, len(children))
			var child oid.ID
			var exists bool

			for i := range children {
				err = child.ReadFromV2(children[i])
				if err != nil {
					return fmt.Errorf("invalid child: %w", err)
				}

				_, exists = mChildren[child]
				if exists {
					return fmt.Errorf("duplicated child %s", child)
				}

				mChildren[child] = struct{}{}
			}

			var mRoot object.Object
			mRoot.SetObjectID(mSplit.GetParent())
			mRoot.SetHeader(mSplit.GetParentHeader())
			mRoot.SetSignature(mSplit.GetParentSignature())

			err = new(Object).ReadFromV2(mRoot)
			if err != nil {
				return fmt.Errorf("invalid root object: %w", err)
			}
		}
	} else if checkFieldPresence {
		return errors.New("missing header")
	}

	mSig := m.GetSignature()
	if mSig != nil {
		err = x.sig.ReadFromV2(*mSig)
		if err != nil {
			return fmt.Errorf("invalid signature: %w", err)
		}
	}

	x.hdr = *hdr
	x.payload = m.GetPayload()

	return nil
}

// TODO: check docs
// ReadFromV2 reads Object from the object.Object message. Checks if the
// message conforms to NeoFS API V2 protocol.
//
// See also WriteToV2.
func (x *Object) ReadFromV2(m object.Object) error {
	return x.readFromV2(m, true)
}

// TODO: check docs
// WriteToV2 writes Container into the container.Container message.
// The message MUST NOT be nil.
//
// See also ReadFromV2.
func (x Object) WriteToV2(m *object.Object) {
	var mID refs.ObjectID
	x.id.WriteToV2(&mID)

	var mSig refs.Signature
	x.sig.WriteToV2(&mSig)

	m.SetObjectID(&mID)
	m.SetHeader(&x.hdr)
	m.SetSignature(&mSig)
	m.SetPayload(x.payload)
}

// TODO: add docs
// Marshal marshals object into a protobuf binary form.
func (x Object) Marshal() []byte {
	var m object.Object
	x.WriteToV2(&m)

	return m.StableMarshal(nil)
}

// TODO: add docs
// Unmarshal unmarshals protobuf binary representation of object.
func (x *Object) Unmarshal(data []byte) error {
	var m object.Object

	err := m.Unmarshal(data)
	if err != nil {
		return err
	}

	return x.readFromV2(m, false)
}

// TODO: add docs
func (x *Object) FinishStructure() {
	x.id.SetSHA256(sha256.Sum256(x.hdr.StableMarshal(nil)))
}

// TODO: add docs
func (x Object) AssertStructure() bool {
	var id [sha256.Size]byte
	x.id.Encode(id[:])

	return sha256.Sum256(x.hdr.StableMarshal(nil)) == id
}

// TODO: add docs
func (x Object) ID() oid.ID {
	return x.id
}

// TODO: add docs
func (x *Object) Sign(signer neofscrypto.Signer) error {
	return x.sig.Calculate(signer, x.id.Marshal())
}

// TODO: add docs
func (x Object) VerifySignature() bool {
	return x.sig.Verify(x.id.Marshal())
}

// TODO: add docs
func (x *Object) Init() {
	var m refs.Version
	version.Current().WriteToV2(&m)

	x.hdr.SetVersion(&m)
}

// TODO: add docs
func (x *Object) SetContainer(cnr cid.ID) {
	var m refs.ContainerID
	cnr.WriteToV2(&m)

	x.hdr.SetContainerID(&m)
}

// TODO: add docs
func (x Object) Container() (res cid.ID) {
	m := x.hdr.GetContainerID()
	if m != nil {
		err := res.ReadFromV2(*m)
		if err != nil {
			panic(fmt.Sprintf("decode container field: %v", err))
		}
	}

	return
}

// TODO: add docs
// SetOwner specifies the owner of the Container. Each Container has exactly
// one owner, so SetOwner MUST be called for instances to be saved in the
// NeoFS.
//
// See also Owner.
func (x *Object) SetOwner(owner user.ID) {
	var m refs.OwnerID
	owner.WriteToV2(&m)

	x.hdr.SetOwnerID(&m)
}

// TODO: add docs
// Owner returns owner of the Container set using SetOwner.
//
// Zero Container has no owner which is incorrect according to NeoFS API
// protocol.
func (x Object) Owner() (res user.ID) {
	m := x.hdr.GetOwnerID()
	if m != nil {
		err := res.ReadFromV2(*m)
		if err != nil {
			panic(fmt.Sprintf("decode owner field: %v", err))
		}
	}

	return
}

// TODO: check docs
// RequiredFields contains the minimum set of object data that must be set
// by the NeoFS user at the stage of creation.
type RequiredFields struct {
	// Identifier of the NeoFS container associated with the object.
	Container cid.ID

	// Object owner's user ID in the NeoFS system.
	Owner user.ID
}

// TODO: check docs
// InitCreation initializes the object instance with minimum set of required fields.
// Object is expected (but not required) to be blank. Object must not be nil.
func InitCreation(dst *Object, rf RequiredFields) {
	dst.Init()
	dst.SetContainer(rf.Container)
	dst.SetOwner(rf.Owner)
}

// TODO: add docs
// SetOwner specifies the owner of the Container. Each Container has exactly
// one owner, so SetOwner MUST be called for instances to be saved in the
// NeoFS.
//
// See also Owner.
func (x *Object) SetPayloadSize(sz uint64) {
	x.hdr.SetPayloadLength(sz)
}

// TODO: add docs
func (x Object) PayloadSize() uint64 {
	return x.hdr.GetPayloadLength()
}

// TODO: add docs
func (x *Object) SetCreationEpoch(epoch uint64) {
	x.hdr.SetCreationEpoch(epoch)
}

// TODO: add docs
func (x Object) CreatedAt() uint64 {
	return x.hdr.GetCreationEpoch()
}

// TODO: add docs
func (x *Object) MakeSession(obj session.Object) {
	var m v2session.Token
	obj.WriteToV2(&m)

	x.hdr.SetSessionToken(&m)
}

// TODO: add docs
func (x Object) Session() (res session.Object) {
	m := x.hdr.GetSessionToken()
	if m != nil {
		err := res.ReadFromV2(*m)
		if err != nil {
			panic(fmt.Sprintf("decode session field: %v", err))
		}
	}

	return
}

// TODO: add docs
type PayloadChecksum struct {
	typ refs.ChecksumType

	hash.Hash
}

// TODO: add docs
func (x *PayloadChecksum) InitSHA256() {
	x.typ = refs.SHA256
	x.Hash = sha256.New()
}

// TODO: add docs
func (x *PayloadChecksum) InitTillichZemor() {
	x.typ = refs.TillichZemor
	x.Hash = tz.New()
}

// TODO: add docs
func (x *Object) SetPayloadChecksum(cs PayloadChecksum) {
	var m refs.Checksum
	m.SetType(cs.typ)
	m.SetSum(cs.Sum(nil))

	x.hdr.SetPayloadHash(&m)
}

// TODO: add docs
func (x Object) InitPayloadVerificationChecksum(cs *PayloadChecksum) {
	switch m := x.hdr.GetPayloadHash(); m.GetType() {
	default:
		panic(fmt.Sprintf("unsupported checksum type %v", m.GetType()))
	case 0, refs.SHA256:
		cs.InitSHA256()
	case refs.TillichZemor:
		cs.InitTillichZemor()
	}
}

// TODO: add docs
func (x Object) AssertPayloadChecksum(cs PayloadChecksum) bool {
	m := x.hdr.GetPayloadHash()
	return m.GetType() == cs.typ && bytes.Equal(m.GetSum(), cs.Sum(nil))
}

// TODO: add docs
type PayloadHomomorphicChecksum struct {
	hash.Hash
}

// TODO: add docs
func (x *PayloadHomomorphicChecksum) Init() {
	x.Hash = sha256.New()
	x.Hash = tz.New()
}

// TODO: add docs
func (x *Object) SetPayloadHomomorphicChecksum(cs PayloadHomomorphicChecksum) {
	var m refs.Checksum
	m.SetType(refs.TillichZemor)
	m.SetSum(cs.Sum(nil))

	x.hdr.SetPayloadHash(&m)
}

type Type struct {
	m object.Type
}

func (x *Type) MakeTombstone() {
	x.m = object.TypeTombstone
}

func (x Type) Tombstone() bool {
	return x.m == object.TypeTombstone
}

func (x *Type) MakeStorageGroup() {
	x.m = object.TypeStorageGroup
}

func (x Type) StorageGroup() bool {
	return x.m == object.TypeStorageGroup
}

func (x *Type) MakeLock() {
	x.m = object.TypeLock
}

func (x Type) Lock() bool {
	return x.m == object.TypeLock
}

func (x *Object) SetType(t Type) {
	x.hdr.SetObjectType(t.m)
}

func (x Object) Type() (res Type) {
	switch x.hdr.GetObjectType() {
	default:
		panic(fmt.Sprintf("unsupported object type %v", x.hdr.GetObjectType()))
	case object.TypeTombstone:
		res.MakeTombstone()
	case object.TypeStorageGroup:
		res.MakeStorageGroup()
	case object.TypeLock:
		res.MakeLock()
	}

	return
}

func (x Type) String() string {
	return x.m.String()
}

// TODO: check docs
// SetPayload sets payload bytes.
func (x *Object) SetPayload(payload []byte) {
	x.payload = payload
}

// TODO: check docs
// Payload returns payload bytes.
func (x Object) Payload() []byte {
	return x.payload
}

// TODO: check docs
// SetAttribute sets Container attribute value by key. Both key and value
// MUST NOT be empty. Attributes set by the creator (owner) are most commonly
// ignored by the NeoFS system and used for application layer. Some attributes
// are so-called system or well-known attributes: they are reserved for system
// needs. System attributes SHOULD NOT be modified using SetAttribute, use
// corresponding methods/functions. List of the reserved keys is documented
// in the particular protocol version.
//
// SetAttribute overwrites existing attribute value.
//
// See also Attribute, IterateAttributes.
func (x *Object) SetAttribute(key, value string) {
	if key == "" {
		panic("empty attribute key")
	} else if value == "" {
		panic("empty attribute value")
	}

	attrs := x.hdr.GetAttributes()
	ln := len(attrs)

	for i := 0; i < ln; i++ {
		if attrs[i].GetKey() == key {
			attrs[i].SetValue(value)
			return
		}
	}

	attrs = append(attrs, object.Attribute{})
	attrs[ln].SetKey(key)
	attrs[ln].SetValue(value)

	x.hdr.SetAttributes(attrs)
}

// TODO: check docs
// Attribute reads value of the Container attribute by key. Empty result means
// attribute absence.
//
// See also SetAttribute, IterateAttributes.
func (x Object) Attribute(key string) string {
	attrs := x.hdr.GetAttributes()
	for i := range attrs {
		if attrs[i].GetKey() == key {
			return attrs[i].GetValue()
		}
	}

	return ""
}

// TODO: check docs
// IterateAttributes iterates over all Container attributes and passes them
// into f. The handler MUST NOT be nil.
//
// See also SetAttribute, Attribute.
func (x Object) IterateAttributes(f func(key, val string)) {
	attrs := x.hdr.GetAttributes()
	for i := range attrs {
		f(attrs[i].GetKey(), attrs[i].GetValue())
	}
}

// TODO: add docs
func LimitLifetime(obj *Object, epoch uint64) {
	obj.SetAttribute(object.SysAttributeExpEpoch, strconv.FormatUint(epoch, 10))
}

// TODO: add docs
func ExpiresAfter(obj Object) (res uint64) {
	attrVal := obj.Attribute(object.SysAttributeExpEpoch)
	if attrVal != "" {
		var err error

		res, err = strconv.ParseUint(attrVal, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("invalid expiration attribute %s: %v", attrVal, err))
		}
	}

	return
}

// TODO: add docs
type Notification struct {
	enabled bool

	epoch uint64

	topic string
}

func (x Notification) Enabled() bool {
	return x.enabled
}

// TODO: add docs
func (x *Notification) SetGenerationTime(epoch uint64) {
	x.enabled = true
	x.epoch = epoch
}

// TODO: add docs
func (x Notification) GenerationTime() uint64 {
	return x.epoch
}

// TODO: check docs
// SetTopic sets optional object notification topic.
func (x *Notification) SetTopic(topic string) {
	x.enabled = true
	x.topic = topic
}

// TODO: check docs
func (x Notification) Topic() string {
	return x.topic
}

// TODO: check docs
func WriteNotification(obj *Object, n Notification) {
	obj.SetAttribute(object.SysAttributeTickEpoch, strconv.FormatUint(n.GenerationTime(), 10))

	if topic := n.Topic(); topic != "" {
		obj.SetAttribute(object.SysAttributeTickTopic, topic)
	}
}

// TODO: check docs
func ReadNotification(obj Object) (res Notification) {
	attrVal := obj.Attribute(object.SysAttributeTickEpoch)
	if attrVal != "" {
		epoch, err := strconv.ParseUint(attrVal, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("invalid notification time attribute %s: %v", attrVal, err))
		}

		res.SetGenerationTime(epoch)
		res.SetTopic(obj.Attribute(object.SysAttributeTickTopic))
	}

	return
}

const attributeName = "Name"

// TODO: check docs
// SetName sets human-readable name of the Container. Name MUST NOT be empty.
//
// See also Name.
func SetName(obj *Object, name string) {
	obj.SetAttribute(attributeName, name)
}

// TODO: check docs
// Name returns container name set using SetName.
//
// Zero Container has no name.
func Name(obj Object) string {
	return obj.Attribute(attributeName)
}

const attributeTimestamp = "Timestamp"

// TODO: check docs
// SetCreationTime writes container's creation time in Unix Timestamp format.
//
// See also CreatedAt.
func SetCreationTime(obj *Object, t time.Time) {
	obj.SetAttribute(attributeTimestamp, strconv.FormatInt(t.Unix(), 10))
}

// TODO: check docs
// CreatedAt returns container's creation time set using SetCreationTime.
//
// Zero Container has zero timestamp (in seconds).
func CreatedAt(obj Object) time.Time {
	var sec int64

	attr := obj.Attribute(attributeTimestamp)
	if attr != "" {
		var err error

		sec, err = strconv.ParseInt(obj.Attribute(attributeTimestamp), 10, 64)
		if err != nil {
			panic(fmt.Sprintf("parse object timestamp: %v", err))
		}
	}

	return time.Unix(sec, 0)
}

const attributeFilename = "FileName"

// TODO: add docs
func SetFilename(obj *Object, filename string) {
	obj.SetAttribute(attributeFilename, filename)
}

// TODO: add docs
func Filename(obj Object) string {
	return obj.Attribute(attributeFilename)
}

const attributeContentType = "Content-Type"

// TODO: add docs
func SetContentType(obj *Object, contentType string) {
	obj.SetAttribute(attributeContentType, contentType)
}

// TODO: add docs
func ContentType(obj Object) string {
	return obj.Attribute(attributeContentType)
}

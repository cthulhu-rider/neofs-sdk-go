package object

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-api-go/v2/object"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
)

// TODO: add docs
type SplitTree struct {
	fin bool

	id uuid.UUID

	root *Object

	children []oid.ID
}

// TODO: add docs
func (x *SplitTree) Init() {
	x.id = uuid.New()
	x.children = make([]oid.ID, 0, 5)
}

// TODO: add docs
func (x *SplitTree) AddChild(id oid.ID) {
	x.children = append(x.children, id)
}

// TODO: add docs
func (x *SplitTree) SetRoot(root Object) {
	x.root = &root
}

// TODO: add docs
func (x *SplitTree) FinishChildren() {
	x.fin = true
}

// TODO: add docs
func (x *Object) WriteSplitTree(s SplitTree) {
	var hdrSplit object.SplitHeader

	binSplitID, err := s.id.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("unexpected error from uuid.UUID.MarshalBinary: %v", err))
	}

	hdrSplit.SetSplitID(binSplitID)

	if s.fin {
		children := make([]refs.ObjectID, len(s.children))

		for i := range s.children {
			s.children[i].WriteToV2(&children[i])
		}

		hdrSplit.SetChildren(children)
	} else if len(s.children) > 0 {
		var prev refs.ObjectID
		s.children[len(s.children)-1].WriteToV2(&prev)

		hdrSplit.SetPrevious(&prev)
	}

	if s.root != nil {
		var idRoot refs.ObjectID
		s.root.id.WriteToV2(&idRoot)

		var sigRoot refs.Signature
		s.root.sig.WriteToV2(&sigRoot)

		hdrSplit.SetParent(&idRoot)
		hdrSplit.SetParentHeader(&s.root.hdr)
		hdrSplit.SetParentSignature(&sigRoot)
	}

	x.hdr.SetSplit(&hdrSplit)
}

// TODO: add docs
type SplitInfo struct {
	m object.SplitInfo
}

// TODO: add docs
func (x *SplitInfo) ReadFromV2(m object.SplitInfo) error {
	var err error
	var id oid.ID

	linker := m.GetLink()
	if linker != nil {
		err = id.ReadFromV2(*linker)
		if err != nil {
			return fmt.Errorf("invalid linker: %w", err)
		}
	}

	last := m.GetLastPart()
	if last != nil {
		err = id.ReadFromV2(*last)
		if err != nil {
			return fmt.Errorf("invalid last child: %w", err)
		}
	} else if linker == nil {
		return errors.New("both linker and last child are empty")
	}

	x.m = m

	return nil
}

// TODO: add docs
func (x SplitInfo) LastChild() (res oid.ID) {
	m := x.m.GetLastPart()
	if m != nil {
		err := res.ReadFromV2(*m)
		if err != nil {
			panic(fmt.Sprintf("unexpected error in last split child resolving: %v", err))
		}
	}

	return
}

// TODO: add docs
func (x *SplitInfo) SetLastChild(last oid.ID) {
	var idV2 refs.ObjectID
	last.WriteToV2(&idV2)

	x.m.SetLastPart(&idV2)
}

// TODO: add docs
func (x SplitInfo) Linker() (res oid.ID) {
	m := x.m.GetLink()
	if m != nil {
		err := res.ReadFromV2(*m)
		panic(fmt.Sprintf("unexpected error in linker resolving: %v", err))
	}

	return
}

// TODO: add docs
func (x *SplitInfo) SetLinker(linker oid.ID) {
	var idV2 refs.ObjectID
	linker.WriteToV2(&idV2)

	x.m.SetLink(&idV2)
}

// TODO: add docs
type ErrSplit struct {
	info SplitInfo
}

// TODO: add docs
func (x ErrSplit) Error() string {
	return "object is split"
}

func (x *ErrSplit) SetInfo(info SplitInfo) {
	x.info = info
}

func (x ErrSplit) Info() SplitInfo {
	return x.info
}

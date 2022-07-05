package object

import (
	"fmt"
	"strings"

	"github.com/nspcc-dev/neofs-api-go/v2/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

type filterState int8

const (
	filterUnspecified filterState = iota
	filterStringEquals
	filterStringNotEquals
	filterNotPresent
	filterPrefixEquals
)

type Filter struct {
	idState filterState
	id      string

	ownerState filterState
	owner      string

	typ object.Type
}

func (x Filter) WriteToV2(m *object.SearchRequestBody) {
	// TODO: optimize allocs
	var fs []object.SearchFilter

	_ = fs

	// FIXME: fill the body
}

func (x *Filter) ByID(id oid.ID) {
	x.idState = filterStringEquals
	x.id = id.EncodeToString()
}

func (x Filter) CustomID() bool {
	return x.idState != filterUnspecified
}

func (x Filter) AssertID(id oid.ID) bool {
	switch x.idState {
	default:
		panic(fmt.Sprintf("unsupported enum value %d", x.idState))
	case filterUnspecified:
		return true
	case filterStringEquals:
		return x.id == id.EncodeToString()
	case filterStringNotEquals:
		return x.id != id.EncodeToString()
	case filterNotPresent:
		return false
	case filterPrefixEquals:
		return strings.HasPrefix(id.EncodeToString(), x.id)
	}
}

func (x *Filter) ByOwner(id user.ID) {
	x.ownerState = filterStringEquals
	x.owner = id.EncodeToString()
}

func (x Filter) CustomOwner() bool {
	return x.ownerState != filterUnspecified
}

func (x Filter) AssertOwner(id user.ID) bool {
	switch x.idState {
	default:
		panic(fmt.Sprintf("unsupported enum value %d", x.idState))
	case filterUnspecified:
		return true
	case filterStringEquals:
		return x.owner == id.EncodeToString()
	case filterStringNotEquals:
		return x.owner != id.EncodeToString()
	case filterNotPresent:
		return false
	case filterPrefixEquals:
		return strings.HasPrefix(id.EncodeToString(), x.owner)
	}
}

func (x *Filter) ByType(t Type) {
	x.typ = t.m
}

func (x Filter) AssertType(t Type) bool {
	return x.typ == t.m
}

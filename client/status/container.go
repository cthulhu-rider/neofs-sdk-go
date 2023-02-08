package apistatus

import (
	"github.com/nspcc-dev/neofs-api-go/v2/container"
	"github.com/nspcc-dev/neofs-api-go/v2/status"
)

// ContainerNotFound describes status of the failure because of the missing container.
// Instances provide Status and StatusV2 interfaces.
type ContainerNotFound struct {
	v2 status.Status
}

const defaultContainerNotFoundMsg = "container not found"

func (x ContainerNotFound) Error() string {
	msg := x.v2.Message()
	if msg == "" {
		msg = defaultContainerNotFoundMsg
	}

	return errMessageStatusV2(
		globalizeCodeV2(container.StatusNotFound, container.GlobalizeFail),
		msg,
	)
}

// implements local interface defined in FromStatusV2 func.
func (x *ContainerNotFound) fromStatusV2(st *status.Status) {
	x.v2 = *st
}

// ToStatusV2 implements StatusV2 interface method.
// If the value was returned by FromStatusV2, returns the source message.
// Otherwise, returns message with
//   - code: CONTAINER_NOT_FOUND;
//   - string message: "container not found";
//   - details: empty.
func (x ContainerNotFound) ToStatusV2() *status.Status {
	x.v2.SetCode(globalizeCodeV2(container.StatusNotFound, container.GlobalizeFail))
	x.v2.SetMessage(defaultContainerNotFoundMsg)
	return &x.v2
}

// ExtendedACLNotFound describes status of the failure because of the missing
// container's extended ACL . Instances provide Status and StatusV2 interfaces.
type ExtendedACLNotFound struct {
	v2 status.Status
}

const defaultExtendedACLNotFoundMsg = "extended ACL not found"

func (x ExtendedACLNotFound) Error() string {
	msg := x.v2.Message()
	if msg == "" {
		msg = defaultExtendedACLNotFoundMsg
	}

	return errMessageStatusV2(
		globalizeCodeV2(container.StatusEACLNotFound, container.GlobalizeFail),
		msg,
	)
}

// implements local interface defined in FromStatusV2 func.
func (x *ExtendedACLNotFound) fromStatusV2(st *status.Status) {
	x.v2 = *st
}

// ToStatusV2 implements StatusV2 interface method.
// If the value was returned by FromStatusV2, returns the source message.
// Otherwise, returns message with
//   - code: EACL_NOT_FOUND;
//   - string message: "extended ACL not found";
//   - details: empty.
func (x ExtendedACLNotFound) ToStatusV2() *status.Status {
	x.v2.SetCode(globalizeCodeV2(container.StatusEACLNotFound, container.GlobalizeFail))
	x.v2.SetMessage(defaultExtendedACLNotFoundMsg)
	return &x.v2
}

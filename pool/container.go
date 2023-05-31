package pool

import (
	"context"

	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// ContainerPut sends request to save container in NeoFS.
//
// See details in [client.Client.ContainerPut].
func (p *Pool) ContainerPut(ctx context.Context, cont container.Container, prm client.PrmContainerPut) (cid.ID, error) {
	c, err := p.sdkClient()
	if err != nil {
		return cid.ID{}, err
	}

	return c.ContainerPut(ctx, cont, prm)
}

// ContainerGet reads NeoFS container by ID.
//
// See details in [client.Client.ContainerGet].
func (p *Pool) ContainerGet(ctx context.Context, id cid.ID, prm client.PrmContainerGet) (container.Container, error) {
	c, err := p.sdkClient()
	if err != nil {
		return container.Container{}, err
	}

	return c.ContainerGet(ctx, id, prm)
}

// ContainerList requests identifiers of the account-owned containers.
//
// See details in [client.Client.ContainerList].
func (p *Pool) ContainerList(ctx context.Context, ownerID user.ID, prm client.PrmContainerList) ([]cid.ID, error) {
	c, err := p.sdkClient()
	if err != nil {
		return []cid.ID{}, err
	}

	return c.ContainerList(ctx, ownerID, prm)
}

// ContainerDelete sends request to remove the NeoFS container.
//
// See details in [client.Client.ContainerDelete].
func (p *Pool) ContainerDelete(ctx context.Context, id cid.ID, prm client.PrmContainerDelete) error {
	c, err := p.sdkClient()
	if err != nil {
		return err
	}

	return c.ContainerDelete(ctx, id, prm)
}

// ContainerEACL reads eACL table of the NeoFS container.
//
// See details in [client.Client.ContainerEACL].
func (p *Pool) ContainerEACL(ctx context.Context, id cid.ID, prm client.PrmContainerEACL) (eacl.Table, error) {
	c, err := p.sdkClient()
	if err != nil {
		return eacl.Table{}, err
	}

	return c.ContainerEACL(ctx, id, prm)
}

// ContainerSetEACL sends request to update eACL table of the NeoFS container.
//
// See details in [client.Client.ContainerSetEACL].
func (p *Pool) ContainerSetEACL(ctx context.Context, table eacl.Table, prm client.PrmContainerSetEACL) error {
	c, err := p.sdkClient()
	if err != nil {
		return err
	}

	return c.ContainerSetEACL(ctx, table, prm)
}

// ContainerAnnounceUsedSpace sends request to announce volume of the space used for the container objects.
//
// See details in [client.Client.ContainerAnnounceUsedSpace].
func (p *Pool) ContainerAnnounceUsedSpace(ctx context.Context, announcements []container.SizeEstimation, prm client.PrmAnnounceSpace) error {
	c, err := p.sdkClient()
	if err != nil {
		return err
	}

	return c.ContainerAnnounceUsedSpace(ctx, announcements, prm)
}

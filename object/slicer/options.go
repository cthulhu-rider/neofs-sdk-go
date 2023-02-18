package slicer

// Options groups Slicer options.
type Options struct {
	objectPayloadLimit uint64

	currentNeoFSEpoch uint64
}

// SetObjectPayloadLimit specifies data size limit for produced physically
// stored objects.
func (x *Options) SetObjectPayloadLimit(l uint64) {
	x.objectPayloadLimit = l
}

// SetCurrentNeoFSEpoch sets current NeoFS epoch.
func (x *Options) SetCurrentNeoFSEpoch(e uint64) {
	x.currentNeoFSEpoch = e
}

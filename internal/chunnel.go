package internal

import "github.com/reymons/jup/internal/wire"

type Channel struct {
	id       wire.CID
	reliable bool
}

func NewChannel(id wire.CID, reliable bool) Channel {
	return Channel{id, reliable}
}

package internal

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/reymons/jup/internal/wire"
)

const bufferSize = 1300

var (
	ErrInvalidPacket = errors.New("invalid packet")
)

var pool = &sync.Pool{
	New: func() any {
		data := make([]byte, bufferSize)
		return NewPacketBuffer(data)
	},
}

func GetPacketBuffer() *PacketBuffer {
	buf := pool.Get().(*PacketBuffer)
	buf.released.Store(false)
	return buf
}

type PacketBuffer struct {
	buf, hdr, payload []byte
	released          atomic.Bool
}

func NewPacketBuffer(buf []byte) *PacketBuffer {
	return &PacketBuffer{
		buf:     buf,
		hdr:     buf[:wire.HdrSize],
		payload: buf[wire.HdrSize:],
	}
}

func (b *PacketBuffer) WriteHeader(hdr *wire.Header) error {
	return hdr.Encode(b.hdr)
}

func (b *PacketBuffer) ReadHeader(hdr *wire.Header) error {
	return hdr.Decode(b.hdr)
}

func (b *PacketBuffer) Buffer() []byte {
	return b.buf
}

func (b *PacketBuffer) PacketBytes() []byte {
	return b.buf[:len(b.hdr)+len(b.payload)]
}

func (b *PacketBuffer) HeaderBytes() []byte {
	return b.hdr
}

func (b *PacketBuffer) Payload() []byte {
	return b.payload
}

func (b *PacketBuffer) SetPacketSize(n int) {
	b.payload = b.buf[wire.HdrSize:n]
}

func (b *PacketBuffer) SetPayloadSize(n int) {
	b.payload = b.buf[wire.HdrSize : wire.HdrSize+n]
}

func (b *PacketBuffer) Release() {
	if b.released.CompareAndSwap(false, true) {
		pool.Put(b)
	}
}

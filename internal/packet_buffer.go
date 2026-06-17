package internal

import (
	"sync"
	"sync/atomic"
)

const bufferSize = 1300

var pool = &sync.Pool{
	New: func() any {
		data := make([]byte, bufferSize)
		return NewPacketBuffer(data)
	},
}

func GetPacketBuffer() *PacketBuffer {
	buf := pool.Get().(*PacketBuffer)
	buf.released.Store(false)
	buf.left = 0
	buf.UnrestrictRight()
	return buf
}

//type PacketBuffer struct {
//	buf, hdr, payload []byte
//	released          atomic.Bool
//}
//
//func NewPacketBuffer(buf []byte) *PacketBuffer {
//	return &PacketBuffer{
//		buf:     buf,
//		hdr:     buf[:wire.HdrSize],
//		payload: buf[wireHdrSize:],
//	}
//}
//
//func (b *PacketBuffer) WriteHeader(hdr *wire.Header) error {
//	return hdr.Encode(b.hdr)
//}
//
//func (b *PacketBuffer) Header() []byte {
//	return b.hdr
//}
//
//func (b *PacketBuffer) Payload() []byte {
//	return b.payload
//}
//
//func (b *PacketBuffer) Bytes() []byte {
//	return b.buffer[:len(b.hdr)+len(b.payload)]
//}
//
//func (b *PacketBuffer) Release() {
//	if b.released.CompareAndSwap(false, true) {
//		pool.Put(b)
//	}
//}

type PacketBuffer struct {
	data        []byte
	left, right int
	released    atomic.Bool
}

func NewPacketBuffer(data []byte) *PacketBuffer {
	return &PacketBuffer{
		data:  data,
		right: len(data),
	}
}

func (b *PacketBuffer) HeaderBytes() []byte {
	return b.data[:b.left]
}

func (b *PacketBuffer) Bytes() []byte {
	return b.data[b.left:b.right]
}

func (b *PacketBuffer) BytesAll() []byte {
	return b.data[:b.right]
}

func (b *PacketBuffer) RestrictLeft(n int) {
	b.left = n
}

func (b *PacketBuffer) RestrictRight(n int) {
	b.right = b.left + n
}

func (b *PacketBuffer) UnrestrictRight() {
	b.right = len(b.data)
}

func (b *PacketBuffer) Release() {
	if b.released.CompareAndSwap(false, true) {
		pool.Put(b)
	}
}

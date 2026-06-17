package wire

import (
	"encoding/binary"
	"io"

	"github.com/reymons/jup/internal/security"
)

type CID = uint16
type UID = uint16

const (
	HdrConnect uint8 = iota + 1
	HdrConnectReply
	HdrConnectFinished
	HdrAck
	HdrUserData
)

const (
	HdrFlagResend uint8 = iota + 1
)

const HdrSize = 26

type Header struct {
	Type    uint8
	Flags   uint8
	User    UID
	Channel CID
	Seq     uint32
	Ack     uint32
	Nonce   [security.NonceSize]byte
}

func (hdr *Header) Encode(data []byte) error {
	if len(data) < HdrSize {
		return io.ErrShortBuffer
	}
	data[0] = hdr.Type
	data[1] = hdr.Flags
	binary.BigEndian.PutUint16(data[2:], hdr.User)
	binary.BigEndian.PutUint16(data[4:], hdr.Channel)
	binary.BigEndian.PutUint32(data[6:], hdr.Seq)
	binary.BigEndian.PutUint32(data[10:], hdr.Ack)
	copy(data[14:], hdr.Nonce[:])
	return nil
}

func (hdr *Header) Decode(data []byte) error {
	if len(data) < HdrSize {
		return io.ErrShortBuffer
	}
	hdr.Type = data[0]
	hdr.Flags = data[1]
	hdr.User = binary.BigEndian.Uint16(data[2:])
	hdr.Channel = binary.BigEndian.Uint16(data[4:])
	hdr.Seq = binary.BigEndian.Uint32(data[6:])
	hdr.Ack = binary.BigEndian.Uint32(data[10:])
	hdr.Nonce = ([security.NonceSize]byte)(data[14 : 14+len(hdr.Nonce)])
	return nil
}

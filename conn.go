package jup

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/reymons/jup/internal"
	"github.com/reymons/jup/internal/security"
	"github.com/reymons/jup/internal/wire"
)

type ChannelConfig struct {
	ID       wire.CID
	Reliable bool
}

type bufferInfo struct {
	buf     *internal.PacketBuffer
	channel wire.CID
}

type Conn struct {
	org      *net.UDPConn
	uid      uint16
	listener bool
	addr     *net.UDPAddr
	symKey   []byte
	channels map[wire.CID]internal.Channel
	cipher   cipher.AEAD
	finished bool
	bufferCh chan bufferInfo
	errorCh  chan error
}

func newConn(org *net.UDPConn, uid uint16, addr *net.UDPAddr, listener bool) *Conn {
	return &Conn{
		org:      org,
		uid:      uid,
		listener: listener,
		addr:     addr,
		channels: map[wire.CID]internal.Channel{},
		bufferCh: make(chan bufferInfo),
		errorCh:  make(chan error),
	}
}

func (conn *Conn) AddChannel(conf ChannelConfig) {
	conn.channels[conf.ID] = internal.NewChannel(conf.ID, conf.Reliable)
}

func (conn *Conn) Close() error {
	return nil
}

func (conn *Conn) initCipher(key []byte) error {
	cipher, err := security.GetCipher(key)
	if err == nil {
		conn.cipher = cipher
	}
	return err
}

func (conn *Conn) sendBytes(data []byte) error {
	var err error
	if conn.listener {
		_, err = conn.org.WriteToUDP(data, conn.addr)
	} else {
		_, err = conn.org.Write(data)
	}
	return err
}

func (conn *Conn) sendPacket(hdr *wire.Header, buf *internal.PacketBuffer) error {
	hdr.User = conn.uid
	if err := buf.WriteHeader(hdr); err != nil {
		return fmt.Errorf("encode header: %w", err)
	}
	return conn.sendBytes(buf.PacketBytes())
}

func (conn *Conn) sendAck(seq uint32) error {
	return nil
}

func (conn *Conn) Addr() string {
	return conn.addr.String()
}

func (conn *Conn) decrypt(nonce [security.NonceSize]byte, buf *internal.PacketBuffer) error {
	aad := buf.HeaderBytes()
	ciphertext := buf.Payload()
	plaintext, err := conn.cipher.Open(ciphertext[:0], nonce[:], ciphertext, aad)
	if err == nil {
		buf.SetPayloadSize(len(plaintext))
	}
	return err
}

func (conn *Conn) encrypt(nonce [security.NonceSize]byte, buf *internal.PacketBuffer) error {
	aad := buf.HeaderBytes()
	plaintext := buf.Payload()
	buf.SetPacketSize(len(buf.Buffer()))
	ciphertext := conn.cipher.Seal(buf.Payload()[:0], nonce[:], plaintext, aad)
	buf.SetPayloadSize(len(ciphertext))
	return nil
}

func (conn *Conn) processPacket(hdr *wire.Header, buf *internal.PacketBuffer) {
	if err := conn.decrypt(hdr.Nonce, buf); err != nil {
		conn.errorCh <- fmt.Errorf("decrypt packet: %w", err)
	} else {
		conn.bufferCh <- bufferInfo{buf, hdr.Channel}
	}
}

func (conn *Conn) ReadBuffer() (*internal.PacketBuffer, wire.CID, error) {
	select {
	case info := <-conn.bufferCh:
		return info.buf, info.channel, nil
	case err := <-conn.errorCh:
		return nil, 0, err
	}
}

func (conn *Conn) AcquireBuffer() *internal.PacketBuffer {
	return internal.GetPacketBuffer()
}

func (conn *Conn) WriteBuffer(buf *internal.PacketBuffer, channel wire.CID) error {
	hdr := wire.Header{
		Type:    wire.HdrUserData,
		Channel: channel,
		User:    conn.uid,
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}
	if err := buf.WriteHeader(&hdr); err != nil {
		return fmt.Errorf("encode header: %w", err)
	}
	if err := conn.encrypt(hdr.Nonce, buf); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return conn.sendBytes(buf.PacketBytes())
}

package jup

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/reymons/jup/internal"
	"github.com/reymons/jup/internal/security"
	"github.com/reymons/jup/internal/wire"
)

var (
	errUnknownConn    = errors.New("unknown connection")
	errUnfinishedConn = errors.New("unfinished connection")
)

func readHeader(buf *internal.PacketBuffer, hdr *wire.Header) error {
	if err := hdr.Decode(buf.BytesAll()); err != nil {
		return err
	}
	buf.RestrictLeft(wire.HdrSize)
	return nil
}

type Listener struct {
	org        *net.UDPConn
	connCh     chan *Conn
	errCh      chan error
	curve      ecdh.Curve
	signingKey ed25519.PrivateKey
	conns      map[wire.UID]*Conn
}

func newListener(org *net.UDPConn, signingKey []byte) *Listener {
	return &Listener{
		org:        org,
		connCh:     make(chan *Conn),
		errCh:      make(chan error),
		signingKey: ed25519.PrivateKey(signingKey),
		conns:      map[wire.UID]*Conn{},
		curve:      ecdh.X25519(),
	}
}

func (ln *Listener) Close() error {
	close(ln.connCh)
	close(ln.errCh)
	return ln.org.Close()
}

// TODO: add cookie challenge on initial request
func (ln *Listener) onConnect(buf *internal.PacketBuffer, addr *net.UDPAddr) error {
	defer buf.Release()
	// extract peer's ECDH public key
	data := buf.Bytes()
	if len(data) != security.CurveSize {
		return io.ErrShortBuffer
	}
	peerPubKey, err := ln.curve.NewPublicKey(data)
	if err != nil {
		return fmt.Errorf("curve.NewPublicKey: %w", err)
	}
	// generate ECDH key pair
	privKey, err := ln.curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("curve.GenerateKey: %w", err)
	}
	pubKey := privKey.PublicKey()
	// derive symmetric key
	symKey, err := security.DeriveSymmetricKey(privKey, peerPubKey)
	if err != nil {
		return fmt.Errorf("derive symmetric key: %w", err)
	}
	// copy public key and peer's public key to the buffer and sign them
	buf.RestrictRight(security.CurveSize*2 + ed25519.SignatureSize)
	data = buf.Bytes()
	copy(data, pubKey.Bytes())
	copy(data[security.CurveSize:], peerPubKey.Bytes())
	sigPos := security.CurveSize * 2
	sig := ed25519.Sign(ln.signingKey, data[:sigPos])
	copy(data[sigPos:], sig)
	// create a connection and send ConnectReply packet
	listener := true
	conn := newConn(ln.org, security.GenerateUID(), addr, listener)
	if err := conn.initCipher(symKey); err != nil {
		return fmt.Errorf("create new conn: %w", err)
	}
	conn.AddChannel(ChannelConfig{ID: wire.HandshakeCID, Reliable: true})
	hdr := wire.Header{Type: wire.HdrConnectReply, Channel: wire.HandshakeCID}
	if err := conn.sendPacket(&hdr, buf); err != nil {
		return fmt.Errorf("send ConnectReply: %w", err)
	}
	ln.conns[conn.uid] = conn
	return nil
}

func (ln *Listener) onFinished(hdr *wire.Header, buf *internal.PacketBuffer) error {
	// ConnectFinished arrives encrypted
	// TODO: Send its own ConnectFinished?
	defer buf.Release()
	conn := ln.conns[hdr.User]
	if conn == nil {
		return errUnknownConn
	}
	if err := conn.decrypt(hdr.Nonce, buf); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	conn.finished = true
	ln.connCh <- conn
	return nil
}

func (ln *Listener) onUserData(hdr *wire.Header, buf *internal.PacketBuffer) error {
	conn := ln.conns[hdr.User]
	if conn == nil {
		return errUnknownConn
	}
	if !conn.finished {
		delete(ln.conns, conn.uid)
		return errUnfinishedConn
	}
	conn.processPacket(hdr, buf)
	return nil
}

func (ln *Listener) acceptOnce() error {
	buf := internal.GetPacketBuffer()
	n, addr, err := ln.org.ReadFromUDP(buf.BytesAll())
	if err != nil {
		return err
	}
	buf.RestrictRight(n)
	var hdr wire.Header
	if err := readHeader(buf, &hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	switch hdr.Type {
	case wire.HdrConnect:
		err = ln.onConnect(buf, addr)
	case wire.HdrConnectFinished:
		err = ln.onFinished(&hdr, buf)
	case wire.HdrUserData:
		err = ln.onUserData(&hdr, buf)
	}
	return err
}

func (ln *Listener) accept() {
	for {
		if err := ln.acceptOnce(); err != nil {
			ln.errCh <- err
		}
	}
}

func (ln *Listener) Accept() (*Conn, error) {
	select {
	case conn := <-ln.connCh:
		return conn, nil
	case err := <-ln.errCh:
		return nil, err
	}
}

type ListenConfig struct {
	Addr       *net.UDPAddr
	SigningKey []byte
}

func Listen(conf ListenConfig) (*Listener, error) {
	org, err := net.ListenUDP("udp", conf.Addr)
	if err != nil {
		return nil, fmt.Errorf("net.ListenUDP: %w", err)
	}
	ln := newListener(org, conf.SigningKey)
	go ln.accept()
	return ln, nil
}

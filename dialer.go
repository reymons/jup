package jup

import (
	"bytes"
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
	errHandshakeFailed  = errors.New("handshake failed")
	errInvalidSignature = errors.New("invalid signature")
	errInvalidPublicKey = errors.New("invalid public key")
	errInvalidPacket    = errors.New("invalid packet")
)

type DialConfig struct {
	Addr         *net.UDPAddr
	VerifyingKey []byte
}

type dialer struct {
	conn         *Conn
	verifyingKey ed25519.PublicKey
	privKey      *ecdh.PrivateKey
	pubKey       *ecdh.PublicKey
	connCh       chan *Conn
	errorCh      chan error
	curve        ecdh.Curve
}

func newDialer(org *net.UDPConn, addr *net.UDPAddr, verifKey []byte) *dialer {
	return &dialer{
		conn:         newConn(org, 0, addr, false),
		verifyingKey: ed25519.PublicKey(verifKey),
		connCh:       make(chan *Conn),
		errorCh:      make(chan error),
		curve:        ecdh.X25519(),
	}
}

func (d *dialer) readOnce(hdr *wire.Header, buf *internal.PacketBuffer) error {
	n, err := d.conn.org.Read(buf.Buffer())
	if err != nil {
		return fmt.Errorf("read from conn: %w", err)
	}
	buf.SetPacketSize(n)
	if err := buf.ReadHeader(hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	return nil
}

func (d *dialer) sendConnect() error {
	buf := internal.GetPacketBuffer()
	defer buf.Release()
	privKey, err := d.curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	pubKey := privKey.PublicKey()
	copy(buf.Payload(), pubKey.Bytes())
	buf.SetPayloadSize(security.CurveSize)
	hdr := wire.Header{Type: wire.HdrConnect}
	if err := d.conn.sendPacket(&hdr, buf); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}
	d.privKey = privKey
	d.pubKey = pubKey
	return nil
}

func (d *dialer) readConnectReply() error {
	buf := internal.GetPacketBuffer()
	defer buf.Release()
	hdr := wire.Header{}
	if err := d.readOnce(&hdr, buf); err != nil {
		return fmt.Errorf("read once: %w", err)
	}
	if hdr.Type != wire.HdrConnectReply {
		return errHandshakeFailed
	}
	payload := buf.Payload()
	if len(payload) != 2*security.CurveSize+ed25519.SignatureSize {
		return io.ErrShortBuffer
	}
	size := security.CurveSize
	sigPos := 2 * size
	pubKey := payload[:size]
	myPubKey := payload[size:sigPos]
	sig := payload[sigPos:]
	mesg := payload[:sigPos]
	// verify the signature and compare public keys
	if !ed25519.Verify(d.verifyingKey, mesg, sig) {
		return errInvalidSignature
	}
	if !bytes.Equal(d.pubKey.Bytes(), myPubKey) {
		return errInvalidPublicKey
	}
	// derive a symmetric key
	key, err := d.curve.NewPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("create new ECDH public key: %w", err)
	}
	symKey, err := security.DeriveSymmetricKey(d.privKey, key)
	if err != nil {
		return fmt.Errorf("derive a symmetric key: %w", err)
	}
	if err := d.conn.initCipher(symKey); err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}
	d.conn.uid = hdr.User
	d.privKey = nil
	d.pubKey = nil
	return nil
}

func (d *dialer) sendConnectFinished() error {
	buf := internal.GetPacketBuffer()
	defer buf.Release()
	hdr := wire.Header{
		Type:    wire.HdrConnectFinished,
		Channel: wire.HandshakeCID,
		User:    d.conn.uid,
	}
	if _, err := rand.Read(hdr.Nonce[:]); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}
	if err := buf.WriteHeader(&hdr); err != nil {
		return fmt.Errorf("encode header: %w", err)
	}
	buf.SetPayloadSize(0)
	if err := d.conn.encrypt(hdr.Nonce, buf); err != nil {
		return fmt.Errorf("encrypt packet: %w", err)
	}
	if err := d.conn.sendBytes(buf.PacketBytes()); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}
	return nil
}

func (d *dialer) readPackets() {
	for {
		buf := internal.GetPacketBuffer()
		hdr := wire.Header{}
		if err := d.readOnce(&hdr, buf); err != nil {
			buf.Release()
			d.conn.errorCh <- fmt.Errorf("read once: %w", err)
			continue
		}
		switch hdr.Type {
		case wire.HdrAck, wire.HdrUserData:
			d.conn.processPacket(&hdr, buf)
		default:
			buf.Release()
			d.conn.errorCh <- errInvalidPacket
		}
	}
}

func (d *dialer) dial() {
	d.conn.AddChannel(ChannelConfig{ID: wire.HandshakeCID, Reliable: true})
	fmt.Printf("Sending Connect...\n")
	if err := d.sendConnect(); err != nil {
		d.errorCh <- fmt.Errorf("send Connect: %w", err)
		return
	}
	fmt.Printf("Reading ConnectReply...\n")
	if err := d.readConnectReply(); err != nil {
		d.errorCh <- fmt.Errorf("read ConnectReply: %w", err)
		return
	}
	fmt.Printf("Sending ConnectFinished...\n")
	if err := d.sendConnectFinished(); err != nil {
		d.errorCh <- fmt.Errorf("send ConnectFinished: %w", err)
		return
	}
	d.connCh <- d.conn
	close(d.errorCh)
	close(d.connCh)
	go d.readPackets()
}

func Dial(conf DialConfig) (*Conn, error) {
	org, err := net.DialUDP("udp", nil, conf.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}
	d := newDialer(org, conf.Addr, conf.VerifyingKey)
	go d.dial()
	select {
	case conn := <-d.connCh:
		return conn, nil
	case err := <-d.errorCh:
		return nil, err
	}
}

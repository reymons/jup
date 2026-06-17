# API

```server
type Message interface {
    Decode(data []byte) error

    Encode(data []byte) error
}

type MessageFactory struct {}

func (f *MessageFactory) Create(data []byte) (Message, error) {
    if len(data) < 1 {
        return nil, io.ErrShortBuffer
    }
    var mesg Message
    switch data[0] {
    case message.TypeEntityInfo:
        mesg := &message.EntityInfo{}
    case message.TypePlayerSession:
        mesg := &message.PlayerSession{}
    default:
        return ErrUnknownMessageType
    }
    if err := mesg.Decode(data); err != nil {
        return nil, fmt.Errorf("decode message: %w", err)
    }
    return mesg, nil
}

type GameTransport struct {
    mesgFactory MessageFactory
}

func (t *GameTransport) onEntityInfo(mesg *message.EntityInfo) error {
}

func (t *GameTransport) onPlayerSession(mesg *message.PlayerSession) error {
}

func (t *GameTransport) onMessage(mesg Message) error {
    switch m := mesg.(type) {
    case *message.EntityInfo:
        return onEntityInfo(m)
    case *message.PlayerSession:
        return onPlayerSession(m)
    default:
        return ErrUnknownMessage
    }
}

func (t *GameTransport) onConn(conn *jup.Conn) {
    defer conn.Close()
    fmt.Printf("New connection: %s\n", conn.Addr())

    conn.AddChannel(jup.ChannelConfig{ID: mainChannel})
    conn.AddChannel(jup.ChannelConfig{ID: animChannel, Reliable: true})

    for {
        data, channel, err := conn.ReadData()
        if err != nil {
            if err == jup.ErrConnClosed {
                fmt.Printf("Connection closed: %s\n", conn.Addr())
            } else {
                logError("read packet: %w", err)
            }
            return
        }
        mesg, err := t.mesgFactory.Create(data.Bytes())
        data.Release()
        if err != nil {
            logError("create message: %w", err)
            continue
        }
        if err := t.onMessage(mesg); err != nil {
            logError("create message: %w", err)
        }
    }
}

func (t *GameTransport) RunServer(addr *net.UDPAddr) error {
    ln, err := jup.Listen(addr)
    if err != nil {
        return fmt.Errorf("listen: %w", err)
    }
    for {
        conn, err := ln.Accept()
        if err != nil {
            logError("accept: %w", err)
            continue
        }
        go t.onConn(conn)
    }
}

func main() {
    addr := &net.UDPAddr{
        IP: net.IPv4(0, 0, 0, 0),
        Port: 7777,
    }
    transport := NewGameTransport()
    if err := transport.RunServer(addr); err != nil {
        logError("run server: %w", err)
    }
}
```

```client
const mainCID = 5

func sendMessage(conn *jup.Conn, mesg Message, channel jup.CID) error {
    data := conn.AcquireBuffer()
    defer data.Release()
    n, err := mesg.Encode(data.Bytes())
    if err != nil {
        return fmt.Errorf("encode entity info: %w", err)
    }
    data.RestrictRight(n)
    if err := conn.WriteData(data, channel); err != nil {
        return fmt.Errorf("send buffer: %w", err)
    }
    return nil
}

func sendSomething(conn *jup.Conn) {
    mesg := message.EntityInfo{
        ID: 1,
        Cmd: message.CmdCreateEntity,
        Pos: message.Vector2{15, 15},
    }
    if err := sendMessage(conn, mesg, mainCID); err != nil {
        logError("send message: %w", err)
    } else {
        fmt.Printf("Send a message: %+v\n", mesg)
    }
}

func main() {
    conn, err := jup.Dial(&net.UDPAddr{
        IP: net.IPv4(0, 0, 0, 0),
        Port: 7777,
    })
    if err != nil {
        logError("dial: %w", err)
        return
    }
    defer conn.Close()
    conn.AddChannel(jup.ChannelConfig{ID: mainCID})
    go sendSomething(conn)
    for {
        data, channel, err := conn.ReadData()
        if err != nil {
            logError("read data: %w", err)
            continue
        }
        if channel != mainCID {
            logError("", ErrInvalidCID)
            return
        }
        mesg, err := mesgFactory.Create(data.Bytes())
        data.Release()
        if err != nil {
            logError("create message: %w", err)
            continue
        }
        fmt.Printf("New message: %+v\n", mesg)
    }
}
```

// Package bot implements a simple Minecraft client that can join a server
// or just ping it for getting information.
//
// Runnable example could be found at examples/ .
package bot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/pablodz/go-mc/chat"
	"github.com/pablodz/go-mc/data/packetid"
	mcnet "github.com/pablodz/go-mc/net"
	pk "github.com/pablodz/go-mc/net/packet"
)

// ProtocolVersion is the protocol version number of minecraft net protocol
const ProtocolVersion = 758
const DefaultPort = mcnet.DefaultPort

type ForgeMod struct {
	ModID   string `nbt:"modid"`
	Version string `nbt:"version"`
}

// JoinServer connect a Minecraft server for playing the game.
// Using roughly the same way to parse address as minecraft.
func (c *Client) JoinServer(addr string) (err error) {
	return c.join(context.Background(), &mcnet.DefaultDialer, addr)
}

// JoinServerWithDialer is similar to JoinServer but using a Dialer.
func (c *Client) JoinServerWithDialer(d *net.Dialer, addr string) (err error) {
	dialer := (*mcnet.Dialer)(d)
	return c.join(context.Background(), dialer, addr)
}

type ModList struct {
	// Assuming that ModList has a field Mods of type []ForgeMod
	Mods []ForgeMod
}

func (m *ModList) ReadFrom(r io.Reader) (int64, error) {
	// Let's assume the data is sent as an int followed by a series of ForgeMod data
	var modCount pk.VarInt
	n, err := modCount.ReadFrom(r)
	if err != nil {
		return n, err
	}

	m.Mods = make([]ForgeMod, modCount)

	for i := 0; i < int(modCount); i++ {
		var mod ForgeMod
		read, err := mod.ReadFrom(r)
		n += read
		if err != nil {
			return n, err
		}

		m.Mods[i] = mod
	}

	return n, nil
}

func (f *ForgeMod) ReadFrom(r io.Reader) (int64, error) {
	var n int64
	var modID, version pk.String

	read, err := modID.ReadFrom(r)
	n += read
	if err != nil {
		return n, err
	}

	read, err = version.ReadFrom(r)
	n += read
	if err != nil {
		return n, err
	}

	f.ModID = string(modID)
	f.Version = string(version)

	return n, nil
}

type ModListReply struct {
	ModCount      pk.VarInt
	ModNames      []pk.String
	ChannelCount  pk.VarInt
	Channels      []pk.Identifier
	RegistryCount pk.VarInt
	Registries    []pk.Identifier
}

func (c *Client) forgeHandshake(p pk.Packet, msgid pk.VarInt) error {
	// Parse the incoming data, which is expected to be a Mod List
	modList := new(ModList)
	if err := p.Scan(modList); err != nil {
		return err
	}

	// Construct the Mod List Reply
	modListReply := &ModListReply{
		ModCount: pk.VarInt(len(c.ForgeMods)),
		ModNames: make([]pk.String, len(c.ForgeMods)),
		// You might want to fill these fields properly depending on your mod setup
		ChannelCount:  pk.VarInt(0),
		Channels:      []pk.Identifier{},
		RegistryCount: pk.VarInt(0),
		Registries:    []pk.Identifier{},
	}

	for i, mod := range c.ForgeMods {
		modListReply.ModNames[i] = pk.String(mod.ModID)
	}

	// Send back the Mod List Reply
	return c.Conn.WritePacket(pk.Marshal(
		packetid.LoginPluginResponse,
		msgid, pk.Boolean(true),
		pk.Opt{Has: true, Field: modListReply},
	))
}

const ForgeProtocolVersion = 2

func (c *Client) join(ctx context.Context, d *mcnet.Dialer, addr string) error {
	const Handshake = 0x00
	// Split Host and Port
	host, portStr, err := net.SplitHostPort(addr)
	var port uint64
	if err != nil {
		var addrErr *net.AddrError
		const missingPort = "missing port in address"
		if errors.As(err, &addrErr) && addrErr.Err == missingPort {
			host = addr
			port = 25565
		} else {
			return LoginErr{"split address", err}
		}
	} else {
		port, err = strconv.ParseUint(portStr, 0, 16)
		if err != nil {
			return LoginErr{"parse port", err}
		}
	}

	// Dial connection
	c.Conn, err = d.DialMCContext(ctx, addr)
	if err != nil {
		return LoginErr{"connect server", err}
	}
	// Handshake
	if len(c.ForgeMods) > 0 {
		// The server address, with the appended FML2 marker
		forgeAddr := fmt.Sprintf(`%s\0FML2\0`, host)

		// Write the packet
		err = c.Conn.WritePacket(pk.Marshal(
			Handshake,
			pk.VarInt(ForgeProtocolVersion), // Forge protocol version
			pk.String(forgeAddr),            // Forge server address
			pk.UnsignedShort(port),          // Port
			pk.Byte(2),                      // Next state (2 for login)
		))
		if err != nil {
			return LoginErr{"handshake forge", err}
		}

	} else {
		// Vanilla working
		err = c.Conn.WritePacket(pk.Marshal(
			Handshake,
			pk.VarInt(ProtocolVersion), // Protocol version
			pk.String(host),            // Host
			pk.UnsignedShort(port),     // Port
			pk.Byte(2),
		))
		if err != nil {
			return LoginErr{"handshake", err}
		}
	}

	// Login Start
	err = c.Conn.WritePacket(pk.Marshal(
		packetid.LoginStart,
		pk.String(c.Auth.Name),
	))
	if err != nil {
		return LoginErr{"login start", err}
	}

	for {
		//Receive Packet
		var p pk.Packet
		if err = c.Conn.ReadPacket(&p); err != nil {
			return LoginErr{"receive packet", err}
		}

		//Handle Packet
		switch p.ID {
		case packetid.LoginDisconnect: //LoginDisconnect
			var reason chat.Message
			err = p.Scan(&reason)
			if err != nil {
				return LoginErr{"disconnect", err}
			}
			return LoginErr{"disconnect", DisconnectErr(reason)}

		case packetid.LoginEncryptionRequest: //Encryption Request
			if err := handleEncryptionRequest(c, p); err != nil {
				return LoginErr{"encryption", err}
			}

		case packetid.LoginSuccess: //Login Success
			err := p.Scan(
				(*pk.UUID)(&c.UUID),
				(*pk.String)(&c.Name),
			)
			if err != nil {
				return LoginErr{"login success", err}
			}
			return nil

		case packetid.SetCompression: //Set Compression
			var threshold pk.VarInt
			if err := p.Scan(&threshold); err != nil {
				return LoginErr{"compression", err}
			}
			c.Conn.SetThreshold(int(threshold))

		case packetid.LoginPluginRequest: //Login Plugin Request
			var (
				msgid   pk.VarInt
				channel pk.Identifier
				data    pk.PluginMessageData
			)
			if err := p.Scan(&msgid, &channel, &data); err != nil {
				return LoginErr{"Login Plugin", err}
			}
			if string(channel) == "fml:handshake" {
				// Forge handshake confirmation
				if err := c.forgeHandshake(p, msgid); err != nil {
					return LoginErr{"forge handshake", err}
				}
			} else {
				// vanilla login plugin
				handler, ok := c.LoginPlugin[string(channel)]
				if ok {
					data, err = handler(data)
					if err != nil {
						return LoginErr{"Login Plugin", err}
					}
				}

				if err := c.Conn.WritePacket(pk.Marshal(
					packetid.LoginPluginResponse,
					msgid, pk.Boolean(ok),
					pk.Opt{Has: ok, Field: data},
				)); err != nil {
					return LoginErr{"login Plugin", err}
				}
			}
		}
	}
}

type LoginErr struct {
	Stage string
	Err   error
}

func (l LoginErr) Error() string {
	return "bot: " + l.Stage + " error: " + l.Err.Error()
}

func (l LoginErr) Unwrap() error {
	return l.Err
}

type DisconnectErr chat.Message

func (d DisconnectErr) Error() string {
	return "disconnect because: " + chat.Message(d).String()
}

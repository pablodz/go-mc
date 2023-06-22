package clientinfo

import (
	"context"
	"github.com/pablodz/go-mc/server/ecs"

	"github.com/pablodz/go-mc/data/packetid"
	pk "github.com/pablodz/go-mc/net/packet"
	"github.com/pablodz/go-mc/server"
)

type ClientInformation struct{}

type Info struct {
	Locale              string
	ViewDistance        int
	ChatMode            byte
	ChatColors          bool
	DisplayedSkinParts  byte
	MainHand            byte // 0: Left, 1: Right.
	EnableTextFiltering bool
	AllowServerListings bool
}

func (c *ClientInformation) Init(g *server.Game) {
	infos := ecs.GetComponent[Info](g.World)
	type updateData struct {
		eid  ecs.Index
		info Info
	}
	updateChan := make(chan updateData)
	g.Add(ecs.FuncSystem(func() {
		for {
			select {
			case info := <-updateChan:
				infos.SetValue(info.eid, info.info)
			default:
				return
			}
		}
	}), "go-mc:ClientInfoSystem", nil)
	g.AddHandler(&server.PacketHandler{
		ID: packetid.ServerboundClientInformation,
		F: func(client *server.Client, player *server.Player, p server.Packet758) error {
			var (
				Locale              pk.String
				ViewDistance        pk.Byte
				ChatMode            pk.VarInt
				ChatColors          pk.Boolean
				DisplayedSkinParts  pk.UnsignedByte
				MainHand            pk.VarInt
				EnableTextFiltering pk.Boolean
				AllowServerListings pk.Boolean
			)
			err := pk.Packet(p).Scan(
				&Locale,
				&ViewDistance,
				&ChatMode,
				&ChatColors,
				&DisplayedSkinParts,
				&MainHand,
				&EnableTextFiltering,
				&AllowServerListings,
			)
			if err != nil {
				return err
			}

			updateChan <- updateData{
				eid: client.Index,
				info: Info{
					Locale:              string(Locale),
					ViewDistance:        int(ViewDistance),
					ChatMode:            byte(ChatMode),
					ChatColors:          bool(ChatColors),
					DisplayedSkinParts:  byte(DisplayedSkinParts),
					MainHand:            byte(MainHand),
					EnableTextFiltering: bool(EnableTextFiltering),
					AllowServerListings: bool(AllowServerListings),
				},
			}
			return nil
		},
	})
}

func (c *ClientInformation) Run(ctx context.Context)                                               {}
func (c *ClientInformation) ClientJoin(client *server.Client, player *server.Player)               {}
func (c *ClientInformation) ClientLeft(client *server.Client, player *server.Player, reason error) {}

package server

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"

	"github.com/pablodz/go-mc/chat"
	"github.com/pablodz/go-mc/data/packetid"
	pk "github.com/pablodz/go-mc/net/packet"
)

// PlayerList is a player list based on linked-list.
// This struct should not be copied after used.
type PlayerList struct {
	maxPlayer int
	clients   map[uuid.UUID]*Player
	// Only the field players is protected by this Mutex.
	// Because others field never change after created.
	playersLock sync.Mutex
}

// NewPlayerList create a PlayerList which implement ListPingHandler.
func NewPlayerList(maxPlayers int) *PlayerList {
	return &PlayerList{
		maxPlayer: maxPlayers,
		clients:   make(map[uuid.UUID]*Player),
	}
}

// Init implement Component for PlayerList
func (p *PlayerList) Init(*Game) {}

// Run implement Component for PlayerList
func (p *PlayerList) Run(context.Context) {}

// ClientJoin implement Component for PlayerList
func (p *PlayerList) ClientJoin(client *Client, player *Player) {
	p.playersLock.Lock()
	defer p.playersLock.Unlock()

	if len(p.clients) >= p.maxPlayer {
		client.WritePacket(Packet758(pk.Marshal(
			packetid.ClientboundDisconnect,
			chat.TranslateMsg("multiplayer.disconnect.server_full"),
		)))
		client.PutErr(errors.New("playerlist: server full"))
		return
	}

	p.clients[player.UUID] = player
}

// ClientLeft implement Component for PlayerList
func (p *PlayerList) ClientLeft(_ *Client, player *Player, _ error) {
	p.playersLock.Lock()
	defer p.playersLock.Unlock()
	delete(p.clients, player.UUID)
}

// CheckPlayer implement LoginChecker for PlayerList
func (p *PlayerList) CheckPlayer(name string, id uuid.UUID, protocol int32) (ok bool, reason chat.Message) {
	p.playersLock.Lock()
	defer p.playersLock.Unlock()
	if len(p.clients) >= p.maxPlayer {
		return false, chat.TranslateMsg("multiplayer.disconnect.server_full")
	}
	return true, chat.Message{}
}

func (p *PlayerList) MaxPlayer() int {
	return p.maxPlayer
}

func (p *PlayerList) OnlinePlayer() int {
	p.playersLock.Lock()
	defer p.playersLock.Unlock()
	return len(p.clients)
}

func (p *PlayerList) PlayerSamples() (sample []PlayerSample) {
	p.playersLock.Lock()
	defer p.playersLock.Unlock()
	// Up to 10 players can be returned
	length := len(p.clients)
	if length > 10 {
		length = 10
	}
	sample = make([]PlayerSample, length)
	var i int
	for _, v := range p.clients {
		sample[i] = PlayerSample{
			Name: v.Name,
			ID:   v.UUID,
		}
		i++
		if i >= length {
			break
		}
	}
	return
}

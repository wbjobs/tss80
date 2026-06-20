package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	EventTypeConnect = iota
	EventTypeAccept
	EventTypeClose
)

type Event struct {
	Type    int
	Pid     uint32
	Tid     uint32
	Saddr   net.IP
	Daddr   net.IP
	Sport   uint16
	Dport   uint16
	Fd      uint64
	Comm    string
}

type Parser struct {
	byteOrder binary.ByteOrder
}

func NewParser() *Parser {
	return &Parser{
		byteOrder: binary.LittleEndian,
	}
}

func (p *Parser) Parse(raw []byte) (*Event, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("raw sample too small: %d bytes", len(raw))
	}

	if len(raw) == 80 {
		return p.parseConnect(raw)
	} else if len(raw) == 80 {
		return p.parseAccept(raw)
	} else if len(raw) == 80 {
		return p.parseClose(raw)
	}

	if len(raw) >= 76 {
		return p.parseConnect(raw)
	}

	return nil, fmt.Errorf("unknown event size: %d", len(raw))
}

func (p *Parser) parseConnect(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	var pid, tid uint32
	var saddr, daddr uint32
	var sport, dport uint16
	var comm [64]byte

	if err := binary.Read(r, p.byteOrder, &pid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &tid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &saddr); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &daddr); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &sport); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &dport); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &comm); err != nil {
		return nil, err
	}

	return &Event{
		Type:  EventTypeConnect,
		Pid:   pid,
		Tid:   tid,
		Saddr: uint32ToIP(saddr),
		Daddr: uint32ToIP(daddr),
		Sport: sport,
		Dport: dport,
		Comm:  strings.TrimRight(string(comm[:]), "\x00"),
	}, nil
}

func (p *Parser) parseAccept(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	var pid, tid uint32
	var saddr, daddr uint32
	var sport, dport uint16
	var comm [64]byte

	if err := binary.Read(r, p.byteOrder, &pid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &tid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &saddr); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &daddr); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &sport); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &dport); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &comm); err != nil {
		return nil, err
	}

	return &Event{
		Type:  EventTypeAccept,
		Pid:   pid,
		Tid:   tid,
		Saddr: uint32ToIP(saddr),
		Daddr: uint32ToIP(daddr),
		Sport: sport,
		Dport: dport,
		Comm:  strings.TrimRight(string(comm[:]), "\x00"),
	}, nil
}

func (p *Parser) parseClose(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	var pid, tid uint32
	var fd uint64
	var comm [64]byte

	if err := binary.Read(r, p.byteOrder, &pid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &tid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &fd); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &comm); err != nil {
		return nil, err
	}

	return &Event{
		Type: EventTypeClose,
		Pid:  pid,
		Tid:  tid,
		Fd:   fd,
		Comm: strings.TrimRight(string(comm[:]), "\x00"),
	}, nil
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(
		byte(v&0xff),
		byte((v>>8)&0xff),
		byte((v>>16)&0xff),
		byte((v>>24)&0xff),
	)
}

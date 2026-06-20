package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	EventTypeInetConnect = 1
	EventTypeInetAccept  = 2
	EventTypeUnixConnect = 3
	EventTypeUnixAccept  = 4
	EventTypeClose       = 5
)

const (
	MaxSunPath = 108
	MaxCommLen = 64
)

type EventHeader struct {
	EventType uint32
	Pid       uint32
	Tid       uint32
	Comm      [MaxCommLen]byte
}

type Event struct {
	Type        uint32
	Pid         uint32
	Tid         uint32
	Saddr       net.IP
	Daddr       net.IP
	Sport       uint16
	Dport       uint16
	Fd          uint64
	Comm        string
	SunPath     string
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
	if len(raw) < 4 {
		return nil, fmt.Errorf("raw sample too small: %d bytes", len(raw))
	}

	eventType := p.byteOrder.Uint32(raw[0:4])

	switch eventType {
	case EventTypeInetConnect:
		return p.parseInetConnect(raw)
	case EventTypeInetAccept:
		return p.parseInetAccept(raw)
	case EventTypeUnixConnect:
		return p.parseUnixConnect(raw)
	case EventTypeUnixAccept:
		return p.parseUnixAccept(raw)
	case EventTypeClose:
		return p.parseClose(raw)
	default:
		return nil, fmt.Errorf("unknown event type: %d (size=%d)", eventType, len(raw))
	}
}

func (p *Parser) parseHeader(r *bytes.Reader) (*EventHeader, error) {
	var hdr EventHeader
	if err := binary.Read(r, p.byteOrder, &hdr.EventType); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &hdr.Pid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &hdr.Tid); err != nil {
		return nil, err
	}
	if err := binary.Read(r, p.byteOrder, &hdr.Comm); err != nil {
		return nil, err
	}
	return &hdr, nil
}

func (p *Parser) parseInetConnect(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	hdr, err := p.parseHeader(r)
	if err != nil {
		return nil, err
	}

	var saddr, daddr uint32
	var sport, dport uint16
	var padding uint32

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
	if err := binary.Read(r, p.byteOrder, &padding); err != nil {
		return nil, err
	}

	return &Event{
		Type:  hdr.EventType,
		Pid:   hdr.Pid,
		Tid:   hdr.Tid,
		Saddr: uint32ToIP(saddr),
		Daddr: uint32ToIP(daddr),
		Sport: sport,
		Dport: dport,
		Comm:  trimNulls(hdr.Comm[:]),
	}, nil
}

func (p *Parser) parseInetAccept(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	hdr, err := p.parseHeader(r)
	if err != nil {
		return nil, err
	}

	var saddr, daddr uint32
	var sport, dport uint16
	var padding uint32

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
	if err := binary.Read(r, p.byteOrder, &padding); err != nil {
		return nil, err
	}

	return &Event{
		Type:  hdr.EventType,
		Pid:   hdr.Pid,
		Tid:   hdr.Tid,
		Saddr: uint32ToIP(saddr),
		Daddr: uint32ToIP(daddr),
		Sport: sport,
		Dport: dport,
		Comm:  trimNulls(hdr.Comm[:]),
	}, nil
}

func (p *Parser) parseUnixConnect(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	hdr, err := p.parseHeader(r)
	if err != nil {
		return nil, err
	}

	var sunPath [MaxSunPath]byte
	if err := binary.Read(r, p.byteOrder, &sunPath); err != nil {
		return nil, err
	}

	var padding uint32
	if err := binary.Read(r, p.byteOrder, &padding); err != nil {
		return nil, err
	}

	return &Event{
		Type:    hdr.EventType,
		Pid:     hdr.Pid,
		Tid:     hdr.Tid,
		Comm:    trimNulls(hdr.Comm[:]),
		SunPath: trimNulls(sunPath[:]),
	}, nil
}

func (p *Parser) parseUnixAccept(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	hdr, err := p.parseHeader(r)
	if err != nil {
		return nil, err
	}

	var sunPath [MaxSunPath]byte
	if err := binary.Read(r, p.byteOrder, &sunPath); err != nil {
		return nil, err
	}

	var padding uint32
	if err := binary.Read(r, p.byteOrder, &padding); err != nil {
		return nil, err
	}

	return &Event{
		Type:    hdr.EventType,
		Pid:     hdr.Pid,
		Tid:     hdr.Tid,
		Comm:    trimNulls(hdr.Comm[:]),
		SunPath: trimNulls(sunPath[:]),
	}, nil
}

func (p *Parser) parseClose(raw []byte) (*Event, error) {
	r := bytes.NewReader(raw)
	hdr, err := p.parseHeader(r)
	if err != nil {
		return nil, err
	}

	var fd uint64
	if err := binary.Read(r, p.byteOrder, &fd); err != nil {
		return nil, err
	}

	return &Event{
		Type: hdr.EventType,
		Pid:  hdr.Pid,
		Tid:  hdr.Tid,
		Fd:   fd,
		Comm: trimNulls(hdr.Comm[:]),
	}, nil
}

func trimNulls(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(
		byte(v&0xff),
		byte((v>>8)&0xff),
		byte((v>>16)&0xff),
		byte((v>>24)&0xff),
	)
}

//go:build !linux

package ebpf

import "fmt"

type ConnectEvent struct {
	Pid   uint32
	Tid   uint32
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Comm  [64]byte
}

type AcceptEvent struct {
	Pid   uint32
	Tid   uint32
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Comm  [64]byte
}

type CloseEvent struct {
	Pid  uint32
	Tid  uint32
	Fd   uint64
	Comm [64]byte
}

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Load(bytecodePath string) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

func (m *Manager) Attach() error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

func (m *Manager) OpenReader() error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

func (m *Manager) ReadEvent() (interface{}, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

func (m *Manager) Close() error {
	return nil
}

func (m *Manager) WaitForInterrupt() {}

//go:build linux

package ebpf

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

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

type Manager struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Load(bytecodePath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	if bytecodePath != "" {
		spec, err := ebpf.LoadCollectionSpec(bytecodePath)
		if err != nil {
			return fmt.Errorf("load bytecode from %s: %w", bytecodePath, err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return fmt.Errorf("create eBPF collection: %w", err)
		}
		m.collection = coll
		return nil
	}

	if len(BPFBytecode) > 0 {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(BPFBytecode))
		if err != nil {
			return m.loadFromObjectFile()
		}
		btfSpec, err := btf.LoadKernelDefaultSpec()
		if err != nil {
			return fmt.Errorf("load kernel BTF: %w", err)
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			BTFSpec: btfSpec,
		})
		if err != nil {
			return m.loadFromObjectFile()
		}
		m.collection = coll
		return nil
	}

	return m.loadFromObjectFile()
}

func (m *Manager) loadFromObjectFile() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	btfSpec, err := btf.LoadKernelDefaultSpec()
	if err != nil {
		return fmt.Errorf("load kernel BTF: %w", err)
	}

	objPath := "bpf/tracepoint.bpf.o"
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec from %s: %w", objPath, err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		BTFSpec: btfSpec,
	})
	if err != nil {
		return fmt.Errorf("create eBPF collection from source: %w", err)
	}
	m.collection = coll
	return nil
}

func (m *Manager) Attach() error {
	if m.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	progs := []struct {
		name   string
		kpkg   string
		isRet  bool
	}{
		{"trace_connect_entry", "__sys_connect", false},
		{"trace_connect_return", "__sys_connect", true},
		{"trace_accept_entry", "__sys_accept4", false},
		{"trace_accept_return", "__sys_accept4", true},
		{"trace_close", "__sys_close", false},
	}

	for _, p := range progs {
		prog := m.collection.Programs[p.name]
		if prog == nil {
			return fmt.Errorf("program %s not found in collection", p.name)
		}

		var lnk link.Link
		var err error

		if p.isRet {
			lnk, err = link.Kretprobe(p.kpkg, prog, nil)
		} else {
			lnk, err = link.Kprobe(p.kpkg, prog, nil)
		}
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", p.name, p.kpkg, err)
		}
		m.links = append(m.links, lnk)
	}

	return nil
}

func (m *Manager) OpenReader() error {
	if m.collection == nil {
		return fmt.Errorf("eBPF collection not loaded")
	}

	eventsMap := m.collection.Maps["events"]
	if eventsMap == nil {
		return fmt.Errorf("events map not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	m.reader = reader
	return nil
}

func (m *Manager) ReadEvent() (interface{}, error) {
	if m.reader == nil {
		return nil, fmt.Errorf("reader not opened")
	}

	record, err := m.reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read ringbuf: %w", err)
	}

	if len(record.RawSample) < 4 {
		return nil, fmt.Errorf("sample too small")
	}

	return record.RawSample, nil
}

func (m *Manager) Close() error {
	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	if m.collection != nil {
		m.collection.Close()
	}
	return nil
}

func (m *Manager) WaitForInterrupt() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

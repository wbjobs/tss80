package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Service struct {
	Pid         uint32
	Name        string
	Cmdline     string
	ContainerID string
	Namespace   string
	Labels      map[string]string
}

type UnixSocketInfo struct {
	Inode  uint64
	Path   string
	Pid    uint32
	Flags  string
	RefCnt string
}

type Mapper struct {
	mu       sync.RWMutex
	services map[uint32]*Service
	byName   map[string][]*Service
	byPort   map[uint16]*Service

	bySocketPath map[string]*Service
	bySocketInode map[uint64]*UnixSocketInfo
	inodeToPath   map[uint64]string
}

func NewMapper() *Mapper {
	return &Mapper{
		services:      make(map[uint32]*Service),
		byName:        make(map[string][]*Service),
		byPort:        make(map[uint16]*Service),
		bySocketPath:  make(map[string]*Service),
		bySocketInode: make(map[uint64]*UnixSocketInfo),
		inodeToPath:   make(map[uint64]string),
	}
}

func (m *Mapper) Refresh() error {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	newServices := make(map[uint32]*Service)
	newByName := make(map[string][]*Service)
	newByPort := make(map[uint16]*Service)

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(proc.Name(), 10, 32)
		if err != nil {
			continue
		}

		svc, err := m.inspectProcess(uint32(pid))
		if err != nil {
			continue
		}
		if svc == nil {
			continue
		}

		newServices[svc.Pid] = svc
		newByName[svc.Name] = append(newByName[svc.Name], svc)
	}

	m.mu.Lock()
	m.services = newServices
	m.byName = newByName
	m.byPort = newByPort
	m.bySocketPath = make(map[string]*Service)
	m.bySocketInode = make(map[uint64]*UnixSocketInfo)
	m.inodeToPath = make(map[uint64]string)
	m.mu.Unlock()

	m.discoverListeners()
	m.discoverUnixSockets()
	return nil
}

func (m *Mapper) inspectProcess(pid uint32) (*Service, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	comm, err := os.ReadFile(filepath.Join(procPath, "comm"))
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(string(comm))

	cmdlineBytes, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return nil, err
	}
	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	svc := &Service{
		Pid:     pid,
		Name:    m.resolveServiceName(pid, name, cmdline),
		Cmdline: cmdline,
		Labels:  make(map[string]string),
	}

	cgroup, err := os.ReadFile(filepath.Join(procPath, "cgroup"))
	if err == nil {
		svc.ContainerID = extractContainerID(string(cgroup))
	}

	netNS, err := os.Readlink(filepath.Join(procPath, "ns", "net"))
	if err == nil {
		svc.Namespace = strings.Trim(netNS, "[]")
	}

	return svc, nil
}

func (m *Mapper) resolveServiceName(pid uint32, comm, cmdline string) string {
	envPath := fmt.Sprintf("/proc/%d/environ", pid)
	envBytes, err := os.ReadFile(envPath)
	if err == nil {
		envs := strings.Split(string(envBytes), "\x00")
		for _, env := range envs {
			if strings.HasPrefix(env, "SERVICE_NAME=") {
				return strings.TrimPrefix(env, "SERVICE_NAME=")
			}
			if strings.HasPrefix(env, "APP_NAME=") {
				return strings.TrimPrefix(env, "APP_NAME=")
			}
		}
	}

	if m.isSystemdService(pid) {
		return comm
	}

	if idx := strings.Index(cmdline, " "); idx > 0 {
		bin := filepath.Base(cmdline[:idx])
		return sanitizeServiceName(bin)
	}
	return sanitizeServiceName(comm)
}

func (m *Mapper) isSystemdService(pid uint32) bool {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "systemd")
}

func (m *Mapper) discoverListeners() {
	m.mu.Lock()
	defer m.mu.Unlock()

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(proc.Name(), 10, 32)
		if err != nil {
			continue
		}

		tcpPath := fmt.Sprintf("/proc/%d/net/tcp", pid)
		f, err := os.Open(tcpPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			if fields[3] != "0A" {
				continue
			}

			localAddr := fields[1]
			colonIdx := strings.LastIndex(localAddr, ":")
			if colonIdx < 0 {
				continue
			}
			portHex := localAddr[colonIdx+1:]
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil {
				continue
			}

			if svc, ok := m.services[uint32(pid)]; ok {
				m.byPort[uint16(port)] = svc
			}
		}
		f.Close()
	}
}

func (m *Mapper) discoverUnixSockets() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.bySocketInode = make(map[uint64]*UnixSocketInfo)
	m.inodeToPath = make(map[uint64]string)
	m.bySocketPath = make(map[string]*Service)

	unixPath := "/proc/net/unix"
	f, err := os.Open(unixPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		inodeStr := fields[6]
		inode, err := strconv.ParseUint(inodeStr, 10, 64)
		if err != nil {
			continue
		}

		path := ""
		if len(fields) > 7 {
			path = fields[7]
		}

		info := &UnixSocketInfo{
			Inode:  inode,
			Path:   path,
			Flags:  fields[2],
			RefCnt: fields[3],
		}

		m.bySocketInode[inode] = info
		if path != "" {
			m.inodeToPath[inode] = path
		}
	}

	m.mapUnixSocketsToPids()
}

func (m *Mapper) mapUnixSocketsToPids() {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(proc.Name(), 10, 32)
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			fdLink := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(fdLink)
			if err != nil {
				continue
			}

			if strings.HasPrefix(target, "socket:[") {
				inodeStr := strings.TrimPrefix(strings.TrimSuffix(target, "]"), "socket:[")
				inode, err := strconv.ParseUint(inodeStr, 10, 64)
				if err != nil {
					continue
				}

				if info, ok := m.bySocketInode[inode]; ok {
					info.Pid = uint32(pid)

					if info.Path != "" {
						if svc, svcOk := m.services[uint32(pid)]; svcOk {
							m.bySocketPath[info.Path] = svc
						}
					}
				}

				if path, ok := m.inodeToPath[inode]; ok && path != "" {
					if svc, svcOk := m.services[uint32(pid)]; svcOk {
						m.bySocketPath[path] = svc
					}
				}
			}
		}
	}
}

func (m *Mapper) FindByPid(pid uint32) *Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.services[pid]
}

func (m *Mapper) FindByPort(port uint16) *Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byPort[port]
}

func (m *Mapper) FindByName(name string) []*Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byName[name]
}

func (m *Mapper) AllServices() map[uint32]*Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[uint32]*Service, len(m.services))
	for k, v := range m.services {
		result[k] = v
	}
	return result
}

func (m *Mapper) FindByContainerID(containerID string) *Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, svc := range m.services {
		if svc.ContainerID == containerID {
			return svc
		}
	}
	return nil
}

func (m *Mapper) FindByUnixSocketPath(path string) *Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bySocketPath[path]
}

func (m *Mapper) FindUnixSocketInfo(inode uint64) *UnixSocketInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bySocketInode[inode]
}

func (m *Mapper) GetSocketPathByInode(inode uint64) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.inodeToPath[inode]
}

func extractContainerID(cgroup string) string {
	lines := strings.Split(cgroup, "\n")
	for _, line := range lines {
		parts := strings.Split(line, "/")
		for _, part := range parts {
			if len(part) >= 12 && isHex(part[:12]) {
				return part[:12]
			}
		}
	}
	return ""
}

func isHex(s string) bool {
	_, err := strconv.ParseUint(s, 16, 64)
	return err == nil
}

func sanitizeServiceName(name string) string {
	name = strings.TrimPrefix(name, "./")
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "_", "-")
	return strings.ToLower(name)
}

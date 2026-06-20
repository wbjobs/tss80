package topology

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tss80/ebpf-topo/internal/event"
	"github.com/tss80/ebpf-topo/internal/process"
)

type Edge struct {
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	SourceAddr  string    `json:"source_addr"`
	TargetAddr  string    `json:"target_addr"`
	TargetPort  uint16    `json:"target_port"`
	Count       int64     `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
}

type Node struct {
	Name        string            `json:"name"`
	Pids        []uint32          `json:"pids"`
	ContainerID string            `json:"container_id,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type Graph struct {
	mu     sync.RWMutex
	Nodes  map[string]*Node  `json:"nodes"`
	Edges  map[string]*Edge  `json:"edges"`
}

func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*Node),
		Edges: make(map[string]*Edge),
	}
}

func (g *Graph) AddEvent(evt *event.Event, mapper *process.Mapper) {
	if evt.Type == event.EventTypeClose {
		return
	}

	svc := mapper.FindByPid(evt.Pid)
	if svc == nil {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.ensureNode(svc)

	switch evt.Type {
	case event.EventTypeConnect:
		targetSvc := mapper.FindByPort(evt.Dport)
		if targetSvc == nil {
			if evt.Daddr.IsLoopback() || isLocalIP(evt.Daddr) {
				targetSvc = &process.Service{
					Pid:  0,
					Name: fmt.Sprintf("unknown:%d", evt.Dport),
				}
			} else {
				targetSvc = &process.Service{
					Pid:  0,
					Name: evt.Daddr.String(),
				}
			}
			g.ensureNode(targetSvc)
		}
		g.addEdge(svc.Name, targetSvc.Name, evt)

	case event.EventTypeAccept:
		sourceSvc := mapper.FindByPort(evt.Sport)
		if sourceSvc == nil {
			if evt.Saddr.IsLoopback() || isLocalIP(evt.Saddr) {
				sourceSvc = &process.Service{
					Pid:  0,
					Name: "unknown-client",
				}
			} else {
				sourceSvc = &process.Service{
					Pid:  0,
					Name: evt.Saddr.String(),
				}
			}
			g.ensureNode(sourceSvc)
		}
		g.addEdge(sourceSvc.Name, svc.Name, evt)
	}
}

func (g *Graph) ensureNode(svc *process.Service) {
	node, ok := g.Nodes[svc.Name]
	if !ok {
		node = &Node{
			Name:        svc.Name,
			Pids:        []uint32{svc.Pid},
			ContainerID: svc.ContainerID,
			Namespace:   svc.Namespace,
			Labels:      svc.Labels,
		}
		g.Nodes[svc.Name] = node
		return
	}

	found := false
	for _, p := range node.Pids {
		if p == svc.Pid {
			found = true
			break
		}
	}
	if !found && svc.Pid > 0 {
		node.Pids = append(node.Pids, svc.Pid)
	}
	if svc.ContainerID != "" && node.ContainerID == "" {
		node.ContainerID = svc.ContainerID
	}
	if svc.Namespace != "" && node.Namespace == "" {
		node.Namespace = svc.Namespace
	}
	for k, v := range svc.Labels {
		if _, exists := node.Labels[k]; !exists {
			node.Labels[k] = v
		}
	}
}

func (g *Graph) addEdge(source, target string, evt *event.Event) {
	key := edgeKey(source, target)
	edge, ok := g.Edges[key]
	if !ok {
		edge = &Edge{
			Source:     source,
			Target:     target,
			SourceAddr: evt.Saddr.String(),
			TargetAddr: evt.Daddr.String(),
			TargetPort: evt.Dport,
			Count:      1,
			LastSeen:   time.Now(),
		}
		g.Edges[key] = edge
		return
	}
	edge.Count++
	edge.LastSeen = time.Now()
	if evt.Dport > 0 {
		edge.TargetPort = evt.Dport
	}
}

func (g *Graph) ToDOT(w io.Writer) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	fmt.Fprintln(w, "digraph microservice_topology {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=filled, color=\"#4A90D9\", fontcolor=white, fontname=\"Arial\"];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(w)

	names := make([]string, 0, len(g.Nodes))
	for name := range g.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		node := g.Nodes[name]
		label := name
		extra := []string{}
		if node.ContainerID != "" {
			extra = append(extra, fmt.Sprintf("container: %s", node.ContainerID[:12]))
		}
		if len(extra) > 0 {
			label = fmt.Sprintf("%s\\n(%s)", name, strings.Join(extra, ", "))
		}
		fmt.Fprintf(w, "  \"%s\" [label=\"%s\"];\n", name, label)
	}
	fmt.Fprintln(w)

	edgeKeys := make([]string, 0, len(g.Edges))
	for k := range g.Edges {
		edgeKeys = append(edgeKeys, k)
	}
	sort.Strings(edgeKeys)

	for _, k := range edgeKeys {
		e := g.Edges[k]
		label := fmt.Sprintf("%d calls", e.Count)
		if e.TargetPort > 0 {
			label = fmt.Sprintf(":%d (%d)", e.TargetPort, e.Count)
		}
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\"];\n", e.Source, e.Target, label)
	}

	fmt.Fprintln(w, "}")
}

func (g *Graph) ToJSON(w io.Writer) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	type jsonOutput struct {
		Nodes map[string]*Node `json:"nodes"`
		Edges []*Edge          `json:"edges"`
	}

	edges := make([]*Edge, 0, len(g.Edges))
	for _, e := range g.Edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].Source+edges[i].Target < edges[j].Source+edges[j].Target
	})

	out := jsonOutput{
		Nodes: g.Nodes,
		Edges: edges,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func edgeKey(source, target string) string {
	return source + "->" + target
}

func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

package topology

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

type EdgeChangeType string

const (
	EdgeAdded   EdgeChangeType = "added"
	EdgeRemoved EdgeChangeType = "removed"
	EdgeUpdated EdgeChangeType = "updated"
)

type NodeChangeType string

const (
	NodeAdded   NodeChangeType = "added"
	NodeRemoved NodeChangeType = "removed"
)

type EdgeChange struct {
	Type   EdgeChangeType `json:"type"`
	Edge   *Edge          `json:"edge"`
	PrevCount int64       `json:"prev_count,omitempty"`
}

type NodeChange struct {
	Type NodeChangeType `json:"type"`
	Node *Node         `json:"node"`
}

type IncrementalUpdate struct {
	Timestamp   time.Time      `json:"timestamp"`
	SeqNo       int64          `json:"seq_no"`
	Nodes       []*NodeChange  `json:"node_changes"`
	Edges       []*EdgeChange  `json:"edge_changes"`
	TotalNodes  int            `json:"total_nodes"`
	TotalEdges  int            `json:"total_edges"`
}

type Snapshot struct {
	Timestamp time.Time
	Nodes     map[string]*Node
	Edges     map[string]*Edge
}

type edgeSnapshot struct {
	count    int64
	lastSeen time.Time
}

type GraphWatcher struct {
	mu sync.Mutex

	graph        *Graph
	lastSnapshot *Snapshot

	prevEdges  map[string]*edgeSnapshot
	prevNodes  map[string]bool

	seqNo      int64
	edgeIdleTTL time.Duration
}

func NewGraphWatcher(graph *Graph) *GraphWatcher {
	return &GraphWatcher{
		graph:       graph,
		prevEdges:   make(map[string]*edgeSnapshot),
		prevNodes:   make(map[string]bool),
		edgeIdleTTL: 2 * time.Minute,
	}
}

func (gw *GraphWatcher) SetEdgeIdleTTL(ttl time.Duration) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.edgeIdleTTL = ttl
}

func (gw *GraphWatcher) CheckTTL() {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	gw.graph.mu.Lock()
	defer gw.graph.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-gw.edgeIdleTTL)

	for key, edge := range gw.graph.Edges {
		if edge.LastSeen.Before(cutoff) {
			delete(gw.graph.Edges, key)
		}
	}

	usedNodes := make(map[string]bool)
	for _, edge := range gw.graph.Edges {
		usedNodes[edge.Source] = true
		usedNodes[edge.Target] = true
	}

	for name := range gw.graph.Nodes {
		if !usedNodes[name] {
			isPidNode := false
			for _, n := range gw.graph.Nodes {
				if n.Name == name && len(n.Pids) > 0 {
					isPidNode = true
					break
				}
			}
			if !isPidNode {
				continue
			}
			_ = isPidNode
		}
	}
}

func (gw *GraphWatcher) CollectIncremental() *IncrementalUpdate {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	gw.graph.mu.RLock()
	defer gw.graph.mu.RUnlock()

	gw.seqNo++
	update := &IncrementalUpdate{
		Timestamp:  time.Now(),
		SeqNo:      gw.seqNo,
		Nodes:      []*NodeChange{},
		Edges:      []*EdgeChange{},
		TotalNodes: len(gw.graph.Nodes),
		TotalEdges: len(gw.graph.Edges),
	}

	currNodes := make(map[string]bool, len(gw.graph.Nodes))
	for name, node := range gw.graph.Nodes {
		currNodes[name] = true
		if !gw.prevNodes[name] {
			update.Nodes = append(update.Nodes, &NodeChange{
				Type: NodeAdded,
				Node: node,
			})
		}
	}
	for name := range gw.prevNodes {
		if !currNodes[name] {
			update.Nodes = append(update.Nodes, &NodeChange{
				Type: NodeRemoved,
				Node: gw.lastSnapshot.Nodes[name],
			})
		}
	}

	currEdges := make(map[string]*edgeSnapshot, len(gw.graph.Edges))
	for key, edge := range gw.graph.Edges {
		prev, existed := gw.prevEdges[key]
		snap := &edgeSnapshot{
			count:    edge.Count,
			lastSeen: edge.LastSeen,
		}
		currEdges[key] = snap

		if !existed {
			update.Edges = append(update.Edges, &EdgeChange{
				Type: EdgeAdded,
				Edge: edge,
			})
		} else if prev.count != edge.Count {
			update.Edges = append(update.Edges, &EdgeChange{
				Type:      EdgeUpdated,
				Edge:      edge,
				PrevCount: prev.count,
			})
		}
	}
	for key, prev := range gw.prevEdges {
		if _, existed := currEdges[key]; !existed {
			var removedEdge *Edge
			if gw.lastSnapshot != nil {
				removedEdge = gw.lastSnapshot.Edges[key]
			}
			if removedEdge == nil {
				removedEdge = &Edge{}
			}
			update.Edges = append(update.Edges, &EdgeChange{
				Type:      EdgeRemoved,
				Edge:      removedEdge,
				PrevCount: prev.count,
			})
		}
	}

	gw.prevNodes = currNodes
	gw.prevEdges = currEdges
	gw.lastSnapshot = gw.takeSnapshotLocked()

	return update
}

func (gw *GraphWatcher) takeSnapshotLocked() *Snapshot {
	nodes := make(map[string]*Node, len(gw.graph.Nodes))
	for k, v := range gw.graph.Nodes {
		pidsCopy := make([]uint32, len(v.Pids))
		copy(pidsCopy, v.Pids)
		labelsCopy := make(map[string]string, len(v.Labels))
		for lk, lv := range v.Labels {
			labelsCopy[lk] = lv
		}
		nodes[k] = &Node{
			Name:        v.Name,
			Pids:        pidsCopy,
			ContainerID: v.ContainerID,
			Namespace:   v.Namespace,
			Labels:      labelsCopy,
		}
	}

	edges := make(map[string]*Edge, len(gw.graph.Edges))
	for k, v := range gw.graph.Edges {
		edges[k] = &Edge{
			Source:     v.Source,
			Target:     v.Target,
			SourceAddr: v.SourceAddr,
			TargetAddr: v.TargetAddr,
			TargetPort: v.TargetPort,
			UnixSocket: v.UnixSocket,
			Protocol:   v.Protocol,
			Count:      v.Count,
			LastSeen:   v.LastSeen,
		}
	}

	return &Snapshot{
		Timestamp: time.Now(),
		Nodes:     nodes,
		Edges:     edges,
	}
}

func (update *IncrementalUpdate) IsEmpty() bool {
	return len(update.Nodes) == 0 && len(update.Edges) == 0
}

func (update *IncrementalUpdate) ToDOTDelta(w io.Writer) {
	if update.IsEmpty() {
		fmt.Fprintf(w, "// Incremental update #%d at %s: no changes\n\n", update.SeqNo, update.Timestamp.Format(time.RFC3339))
		return
	}

	fmt.Fprintf(w, "// Incremental update #%d at %s\n", update.SeqNo, update.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "// Total: %d nodes, %d edges\n", update.TotalNodes, update.TotalEdges)
	fmt.Fprintln(w, "digraph topology_delta {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=filled, fontname=\"Arial\"];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=10];")
	fmt.Fprintln(w)

	sort.Slice(update.Nodes, func(i, j int) bool {
		if update.Nodes[i].Node == nil || update.Nodes[j].Node == nil {
			return false
		}
		return update.Nodes[i].Node.Name < update.Nodes[j].Node.Name
	})

	for _, nc := range update.Nodes {
		if nc.Node == nil {
			continue
		}
		var color, fontcolor string
		var prefix string
		switch nc.Type {
		case NodeAdded:
			color = "#2ECC71"
			fontcolor = "white"
			prefix = "// [ADDED] "
		case NodeRemoved:
			color = "#E74C3C"
			fontcolor = "white"
			prefix = "// [REMOVED] "
		}
		fmt.Fprintf(w, "  %s\n", prefix+nc.Node.Name)
		fmt.Fprintf(w, "  \"%s\" [color=\"%s\", fontcolor=\"%s\", label=\"%s\"];\n",
			nc.Node.Name, color, fontcolor, nc.Node.Name)
	}
	fmt.Fprintln(w)

	sort.Slice(update.Edges, func(i, j int) bool {
		if update.Edges[i].Edge == nil || update.Edges[j].Edge == nil {
			return false
		}
		return update.Edges[i].Edge.Source+update.Edges[i].Edge.Target <
			update.Edges[j].Edge.Source+update.Edges[j].Edge.Target
	})

	for _, ec := range update.Edges {
		if ec.Edge == nil {
			continue
		}
		var color, style, prefix string
		var label string

		switch ec.Type {
		case EdgeAdded:
			color = "#2ECC71"
			style = "bold"
			prefix = "// [ADDED] "
		case EdgeRemoved:
			color = "#E74C3C"
			style = "dotted"
			prefix = "// [REMOVED] "
		case EdgeUpdated:
			color = "#F1C40F"
			style = "bold"
			prefix = fmt.Sprintf("// [UPDATED] count: %d -> %d ", ec.PrevCount, ec.Edge.Count)
		}

		if ec.Edge.Protocol == "unix" {
			socketName := ec.Edge.UnixSocket
			if len(socketName) > 30 {
				socketName = "..." + socketName[len(socketName)-27:]
			}
			label = fmt.Sprintf("UDS: %s (%d calls)", socketName, ec.Edge.Count)
			if style == "" {
				style = "dashed"
			} else {
				style = style + ",dashed"
			}
		} else {
			label = fmt.Sprintf("%d calls", ec.Edge.Count)
			if ec.Edge.TargetPort > 0 {
				label = fmt.Sprintf(":%d (%d calls)", ec.Edge.TargetPort, ec.Edge.Count)
			}
		}

		fmt.Fprintf(w, "  %s%s -> %s\n", prefix, ec.Edge.Source, ec.Edge.Target)
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [color=\"%s\", style=\"%s\", label=\"%s\"];\n",
			ec.Edge.Source, ec.Edge.Target, color, style, label)
	}

	fmt.Fprintln(w, "}")
	fmt.Fprintln(w)
}

func (update *IncrementalUpdate) ToJSON(w io.Writer) error {
	type deltaSummary struct {
		NodesAdded    int `json:"nodes_added"`
		NodesRemoved  int `json:"nodes_removed"`
		EdgesAdded    int `json:"edges_added"`
		EdgesRemoved  int `json:"edges_removed"`
		EdgesUpdated  int `json:"edges_updated"`
		TotalNodes    int `json:"total_nodes"`
		TotalEdges    int `json:"total_edges"`
	}

	type jsonDelta struct {
		Timestamp    string        `json:"timestamp"`
		SeqNo        int64         `json:"seq_no"`
		NodeChanges  []*NodeChange `json:"node_changes"`
		EdgeChanges  []*EdgeChange `json:"edge_changes"`
		Summary      deltaSummary  `json:"summary"`
	}

	summary := deltaSummary{
		TotalNodes: update.TotalNodes,
		TotalEdges: update.TotalEdges,
	}
	for _, nc := range update.Nodes {
		switch nc.Type {
		case NodeAdded:
			summary.NodesAdded++
		case NodeRemoved:
			summary.NodesRemoved++
		}
	}
	for _, ec := range update.Edges {
		switch ec.Type {
		case EdgeAdded:
			summary.EdgesAdded++
		case EdgeRemoved:
			summary.EdgesRemoved++
		case EdgeUpdated:
			summary.EdgesUpdated++
		}
	}

	out := jsonDelta{
		Timestamp:   update.Timestamp.Format(time.RFC3339),
		SeqNo:       update.SeqNo,
		NodeChanges: update.Nodes,
		EdgeChanges: update.Edges,
		Summary:     summary,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func (update *IncrementalUpdate) ToText(w io.Writer) {
	fmt.Fprintf(w, "=== Topology Delta #%d ===\n", update.SeqNo)
	fmt.Fprintf(w, "Timestamp : %s\n", update.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "Total Nodes: %d, Total Edges: %d\n", update.TotalNodes, update.TotalEdges)

	addedN, removedN := 0, 0
	addedE, removedE, updatedE := 0, 0, 0

	for _, nc := range update.Nodes {
		switch nc.Type {
		case NodeAdded:
			addedN++
		case NodeRemoved:
			removedN++
		}
	}
	for _, ec := range update.Edges {
		switch ec.Type {
		case EdgeAdded:
			addedE++
		case EdgeRemoved:
			removedE++
		case EdgeUpdated:
			updatedE++
		}
	}

	fmt.Fprintf(w, "Summary   : +%d nodes, -%d nodes | +%d edges, -%d edges, ~%d updated\n",
		addedN, removedN, addedE, removedE, updatedE)

	if len(update.Nodes) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Node Changes:")
		for _, nc := range update.Nodes {
			if nc.Node == nil {
				continue
			}
			var tag string
			switch nc.Type {
			case NodeAdded:
				tag = "[+]"
			case NodeRemoved:
				tag = "[-]"
			}
			fmt.Fprintf(w, "  %s %s (pids: %v)\n", tag, nc.Node.Name, nc.Node.Pids)
		}
	}

	if len(update.Edges) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Edge Changes:")
		sort.Slice(update.Edges, func(i, j int) bool {
			if update.Edges[i].Edge == nil || update.Edges[j].Edge == nil {
				return false
			}
			return update.Edges[i].Edge.Source+update.Edges[i].Edge.Target <
				update.Edges[j].Edge.Source+update.Edges[j].Edge.Target
		})
		for _, ec := range update.Edges {
			if ec.Edge == nil {
				continue
			}
			var tag string
			var detail string
			switch ec.Type {
			case EdgeAdded:
				tag = "[+]"
				if ec.Edge.Protocol == "unix" {
					detail = fmt.Sprintf("UDS=%s", ec.Edge.UnixSocket)
				} else if ec.Edge.TargetPort > 0 {
					detail = fmt.Sprintf("port=%d", ec.Edge.TargetPort)
				}
			case EdgeRemoved:
				tag = "[-]"
				detail = fmt.Sprintf("prev_count=%d", ec.PrevCount)
			case EdgeUpdated:
				tag = "[~]"
				detail = fmt.Sprintf("count: %d -> %d", ec.PrevCount, ec.Edge.Count)
			}
			fmt.Fprintf(w, "  %s %s -> %s (%s, calls=%d) %s\n",
				tag, ec.Edge.Source, ec.Edge.Target,
				strings.ToUpper(ec.Edge.Protocol), ec.Edge.Count, detail)
		}
	}

	fmt.Fprintln(w, "")
}

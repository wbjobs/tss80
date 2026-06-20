//go:build linux

package ebpf

import _ "embed"

//go:embed tracepoint_bpf.o
var BPFBytecode []byte

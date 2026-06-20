BPF_SRC = bpf/tracepoint.bpf.c
BPF_OBJ = bpf/tracepoint.bpf.o
CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all build bpf clean generate install

all: bpf build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) \
		-g -O2 -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@

generate: bpf
	go generate ./...

build:
	go build -o ebpf-topo .

install: build
	install -m 755 ebpf-topo /usr/local/bin/

clean:
	rm -f $(BPF_OBJ) ebpf-topo
	go clean

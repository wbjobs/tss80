package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tss80/ebpf-topo/internal/ebpf"
	"github.com/tss80/ebpf-topo/internal/event"
	"github.com/tss80/ebpf-topo/internal/process"
	"github.com/tss80/ebpf-topo/internal/topology"
)

var (
	outputFormat    string
	outputFile      string
	duration        time.Duration
	refreshInterval time.Duration
	bytecodeFile    string
	showVersion     bool
)

var Version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "ebpf-topo",
	Short: "eBPF-based microservice dependency topology generator",
	Long: `ebpf-topo is a CLI tool that leverages eBPF to trace network syscalls
in real time, automatically discovering microservice dependencies and
generating topology graphs (DOT or JSON format).

No application code changes or extra API endpoints are required.
The tool traces connect/accept/close syscalls to build a complete
picture of which services communicate with each other over the network.`,
	RunE: runTrace,
}

func init() {
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "dot", "Output format: dot or json")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.Flags().DurationVarP(&duration, "duration", "d", 0, "Trace duration (0 = run until interrupted)")
	rootCmd.Flags().DurationVar(&refreshInterval, "refresh", 5*time.Second, "Process/service mapping refresh interval")
	rootCmd.Flags().StringVarP(&bytecodeFile, "bytecode", "b", "", "Path to pre-compiled eBPF bytecode (.o file)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Print version information")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ebpf-topo version %s (GOOS=%s GOARCH=%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		},
	})
}

func Execute() {
	if showVersion {
		fmt.Printf("ebpf-topo version %s\n", Version)
		os.Exit(0)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runTrace(cmd *cobra.Command, args []string) error {
	if err := checkPrivileges(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[*] Starting eBPF-based microservice topology tracer v%s\n", Version)
	fmt.Fprintf(os.Stderr, "[*] Output format: %s\n", outputFormat)

	mgr := ebpf.NewManager()
	defer mgr.Close()

	fmt.Fprintf(os.Stderr, "[*] Loading eBPF programs...\n")
	if err := mgr.Load(bytecodeFile); err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[*] Attaching eBPF probes...\n")
	if err := mgr.Attach(); err != nil {
		return fmt.Errorf("attach eBPF: %w", err)
	}

	if err := mgr.OpenReader(); err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}

	mapper := process.NewMapper()
	parser := event.NewParser()
	graph := topology.NewGraph()

	fmt.Fprintf(os.Stderr, "[*] Performing initial service discovery...\n")
	if err := mapper.Refresh(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Warning: initial service discovery failed: %v\n", err)
	}

	services := mapper.AllServices()
	fmt.Fprintf(os.Stderr, "[*] Discovered %d services\n", len(services))
	for _, svc := range services {
		fmt.Fprintf(os.Stderr, "    - %s (pid: %d)\n", svc.Name, svc.Pid)
	}

	refreshTicker := time.NewTicker(refreshInterval)
	defer refreshTicker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	var timeout <-chan time.Time
	if duration > 0 {
		timeout = time.After(duration)
	}

	fmt.Fprintf(os.Stderr, "[*] Tracing network connections... (Press Ctrl+C to stop)\n")

loop:
	for {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\n[*] Received interrupt signal, stopping...\n")
			break loop

		case <-timeout:
			fmt.Fprintf(os.Stderr, "\n[*] Duration reached, stopping...\n")
			break loop

		case <-refreshTicker.C:
			if err := mapper.Refresh(); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Service refresh error: %v\n", err)
			}

		default:
			raw, err := mgr.ReadEvent()
			if err != nil {
				continue
			}

			rawBytes, ok := raw.([]byte)
			if !ok {
				continue
			}

			evt, err := parser.Parse(rawBytes)
			if err != nil {
				continue
			}

			if evt.Type == event.EventTypeClose {
				continue
			}

			graph.AddEvent(evt, mapper)
		}
	}

	fmt.Fprintf(os.Stderr, "[*] Generating topology output...\n")
	return writeOutput(graph)
}

func checkPrivileges() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("eBPF is only supported on Linux. Current OS: %s", runtime.GOOS)
	}
	if os.Getuid() != 0 {
		return fmt.Errorf("this tool requires root privileges to load eBPF programs. Run with sudo or as root")
	}
	return nil
}

func writeOutput(graph *topology.Graph) error {
	var writer *os.File
	if outputFile != "" {
		dir := filepath.Dir(outputFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		writer = f
	} else {
		writer = os.Stdout
	}

	switch outputFormat {
	case "dot":
		graph.ToDOT(writer)
	case "json":
		if err := graph.ToJSON(writer); err != nil {
			return fmt.Errorf("write JSON: %w", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s (use 'dot' or 'json')", outputFormat)
	}

	return nil
}

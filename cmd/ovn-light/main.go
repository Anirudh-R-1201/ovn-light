// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/trozet/ovn-light/internal/app"
	"github.com/trozet/ovn-light/internal/kube"
	"github.com/trozet/ovn-light/internal/model"
	"github.com/trozet/ovn-light/internal/web"
	"k8s.io/apimachinery/pkg/labels"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "capture" || args[0] == "serve") {
		command = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("ovn-light "+command, flag.ContinueOnError)
	addr := fs.String("listen", "127.0.0.1:8080", "HTTP listen address (use port-forward for cluster access)")
	demo := fs.Bool("demo", false, "Use explicitly synthetic evidence; writes are always disabled")
	snapshotFile := fs.String("snapshot", "", "Read a captured snapshot; writes are always disabled")
	kubeconfig := fs.String("kubeconfig", "", "Kubeconfig file; defaults to in-cluster or normal kubeconfig loading")
	contextName := fs.String("context", "", "Kubeconfig context")
	namespace := fs.String("ovn-namespace", "ovn-kubernetes", "Namespace containing existing OVN and OVS pods")
	nbdb := fs.String("nb-db", "unix:/var/run/ovn/ovnnb_db.sock", "OVN NB database address accessible inside the controller container")
	sbdb := fs.String("sb-db", "unix:/var/run/ovn/ovnsb_db.sock", "OVN SB database address accessible inside the controller container")
	interval := fs.Duration("interval", 30*time.Second, "Time between completed collection attempts")
	maxDetraces := fs.Int("max-detraces", 64, "Maximum UFID translation lookups per node per collection")
	nodeSelector := fs.String("collection-node-selector", "", "Inspect only nodes matching this Kubernetes label selector; inventory remains cluster-wide")
	concurrency := fs.Int("collection-concurrency", 3, "Maximum concurrent node collections (1–16)")
	metadataTTL := fs.Duration("metadata-cache-ttl", time.Minute, "Maximum age of cached OVN tables and translations (5s–5m)")
	offloadGrace := fs.Duration("offload-grace", time.Minute, "Minimum sustained software activity before an offload issue (30s–10m)")
	writes := fs.Bool("enable-writes", false, "Enable reviewed Kubernetes changes using server credentials")
	dataDir := fs.String("data-dir", "", "Persistent directory for change audit records (required for writes)")
	output := fs.String("output", "ovn-light-snapshot.json", "Output file for capture command")
	showVersion := fs.Bool("version", false, "Print version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *demo && *snapshotFile != "" {
		return fmt.Errorf("choose either --demo or --snapshot")
	}
	if *interval < 5*time.Second {
		return fmt.Errorf("interval must be at least 5s")
	}
	if *maxDetraces < 1 || *maxDetraces > 1024 {
		return fmt.Errorf("max-detraces must be between 1 and 1024")
	}
	if _, err := labels.Parse(*nodeSelector); err != nil {
		return fmt.Errorf("invalid collection-node-selector: %w", err)
	}
	if *concurrency < 1 || *concurrency > 16 {
		return fmt.Errorf("collection-concurrency must be 1–16")
	}
	if *metadataTTL < 5*time.Second || *metadataTTL > 5*time.Minute {
		return fmt.Errorf("metadata-cache-ttl must be 5s–5m")
	}
	if *offloadGrace < 30*time.Second || *offloadGrace > 10*time.Minute {
		return fmt.Errorf("offload-grace must be 30s–10m")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	mode := "live"
	var client *kube.Client
	var collector *kube.Collector
	var snapshot model.Snapshot
	if *demo {
		mode = "demo"
		snapshot = app.Demo()
	} else if *snapshotFile != "" {
		mode = "snapshot"
		f, err := os.Open(*snapshotFile)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = json.NewDecoder(http.MaxBytesReader(nil, f, 256<<20)).Decode(&snapshot); err != nil {
			return err
		}
		if snapshot.Version != 1 {
			return fmt.Errorf("unsupported snapshot version %d", snapshot.Version)
		}
	} else {
		var err error
		client, err = kube.New(*kubeconfig, *contextName)
		if err != nil {
			return err
		}
		collector = &kube.Collector{NodeSelector: *nodeSelector, RoutingEnabled: true, Client: client, Namespace: *namespace, NBDB: *nbdb, SBDB: *sbdb, MaxDetraces: *maxDetraces, Concurrency: *concurrency, CacheTTL: *metadataTTL}
	}
	if command == "capture" {
		if collector != nil {
			var err error
			snapshot, err = collector.Capture(ctx)
			if err != nil {
				return err
			}
		}
		b, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(*output, b, 0600); err != nil {
			return err
		}
		log.Printf("Captured %d nodes to %s", len(snapshot.Nodes), *output)
		return nil
	}
	token := strings.TrimSpace(os.Getenv("OVN_LIGHT_TOKEN"))
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return err
	}
	loopback := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if token == "" && (!loopback || mode == "live") {
		return fmt.Errorf("set OVN_LIGHT_TOKEN (at least 24 characters) for live access or a non-loopback listener")
	}
	if token != "" && len(token) < 24 {
		return fmt.Errorf("OVN_LIGHT_TOKEN must be at least 24 characters")
	}
	if *writes && mode != "live" {
		return fmt.Errorf("writes cannot be enabled in %s mode", mode)
	}
	if *writes && *dataDir == "" {
		return fmt.Errorf("--enable-writes requires --data-dir for audit records")
	}
	a, err := app.New(mode, *dataDir, client, collector, *writes)
	if err != nil {
		return err
	}
	a.OffloadGrace = *offloadGrace
	if collector == nil {
		if mode == "demo" {
			a.Load(app.DemoBaseline(snapshot))
		}
		a.Load(snapshot)
	} else {
		go a.Run(ctx, *interval)
	}
	server := web.Server(*addr, web.Handler(a, token))
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("OVN-Light %s listening on http://%s (mode=%s, writes=%t)", version, *addr, a.Mode, a.Writes)
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

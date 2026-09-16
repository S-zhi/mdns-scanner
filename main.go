package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mdns-scanner/pkg/output"
	"mdns-scanner/pkg/parser"
	"mdns-scanner/pkg/probe"
	"mdns-scanner/pkg/target"
)

func main() {
	var (
		targetStr   string
		portStr     string
		concurrency int
		timeoutSec  int
		asJSON      bool
	)

	flag.StringVar(&targetStr, "t", "", "Target IP or CIDR (e.g. 192.168.1.0/24 or 192.168.1.10)")
	flag.StringVar(&targetStr, "target", "", "Target IP or CIDR")
	flag.StringVar(&targetStr, "i", "", "Target IP or CIDR (alias)")

	flag.StringVar(&portStr, "p", "5353", "Target port or port range (e.g. 5353, 5000-5005)")
	flag.StringVar(&portStr, "port", "5353", "Target port or port range")

	// Default 100 workers and 2s timeout as specified
	flag.IntVar(&concurrency, "c", 100, "Number of concurrent workers (default 100)")
	flag.IntVar(&concurrency, "concurrency", 100, "Number of concurrent workers")

	flag.IntVar(&timeoutSec, "timeout", 2, "Probe timeout in seconds (default 2)")
	flag.BoolVar(&asJSON, "json", false, "Output results in JSON format")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -t <target> [-p <port>] [-c <concurrency>] [--timeout <seconds>] [--json]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -t 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -i 192.168.1.10 -p 5353,5000-5005\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s 192.168.1.0/24\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Positional argument fallback
	if targetStr == "" && flag.NArg() > 0 {
		targetStr = flag.Arg(0)
	}

	if targetStr == "" {
		fmt.Fprintln(os.Stderr, "Error: missing target IP or CIDR network block")
		flag.Usage()
		os.Exit(1)
	}

	ports, err := target.ParsePorts(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing ports %q: %v\n", portStr, err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	targetsChan, err := target.GenerateTargets(ctx, targetStr, ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing target generator: %v\n", err)
		os.Exit(1)
	}

	probeConfig := probe.Config{
		Concurrency: concurrency,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		Retries:     1,
		QueryNames: []string{
			"_services._dns-sd._udp.local.",
		},
	}

	engine := probe.NewEngine(probeConfig)
	rawResults := engine.Run(ctx, targetsChan)

	aggregator := parser.NewAggregator()
	for raw := range rawResults {
		aggregator.ProcessRawResponse(raw)
	}

	formatter := output.NewFormatter(os.Stdout, asJSON)
	assets := aggregator.GetAllAssets()
	for _, asset := range assets {
		_ = formatter.PrintDeviceAsset(asset)
	}
}

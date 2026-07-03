package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/natedadson/cloud-security-scanner/internal/config"
	"github.com/natedadson/cloud-security-scanner/pkg/aws"
	"github.com/natedadson/cloud-security-scanner/pkg/report"
	"github.com/natedadson/cloud-security-scanner/pkg/scanner"
)

func main() {
	// Command line flags
	var (
		profile  = flag.String("profile", "default", "AWS profile to use")
		region   = flag.String("region", "us-east-1", "AWS region")
		output   = flag.String("output", "scan-report.json", "Output file path")
		format   = flag.String("format", "json", "Output format (json, html)")
		verbose  = flag.Bool("verbose", false, "Enable verbose output")
		help     = flag.Bool("help", false, "Show help")
	)

	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Load configuration
	cfg := config.Config{
		Profile: *profile,
		Region:  *region,
		Verbose: *verbose,
	}

	fmt.Println("🔐 Cloud Security Scanner")
	fmt.Println("==========================")
	fmt.Printf("Profile: %s\n", cfg.Profile)
	fmt.Printf("Region: %s\n", cfg.Region)
	fmt.Println()

	// Initialize AWS session
	session, err := aws.NewSession(cfg)
	if err != nil {
		log.Fatalf("Failed to create AWS session: %v", err)
	}

	// Run security scan
	scanner := scanner.NewScanner(session, cfg)
	results, err := scanner.Scan()
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Generate report
	reporter := report.NewReporter(results)
	if err := reporter.Export(*output, *format); err != nil {
		log.Fatalf("Failed to generate report: %v", err)
	}

	fmt.Printf("\n✅ Scan complete! Report saved to: %s\n", *output)
}

func printHelp() {
	fmt.Println("Cloud Security Scanner - AWS Security Assessment Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  scanner [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -profile string    AWS profile to use (default: default)")
	fmt.Println("  -region string     AWS region (default: us-east-1)")
	fmt.Println("  -output string     Output file path (default: scan-report.json)")
	fmt.Println("  -format string     Output format: json, html (default: json)")
	fmt.Println("  -verbose           Enable verbose output")
	fmt.Println("  -help              Show this help")
}

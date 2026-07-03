package report

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/natedadson/cloud-security-scanner/pkg/scanner"
)

type Reporter struct {
	Results *scanner.ScanResult
}

func NewReporter(results *scanner.ScanResult) *Reporter {
	return &Reporter{
		Results: results,
	}
}

func (r *Reporter) Export(filename string, format string) error {
	switch format {
	case "json":
		return r.exportJSON(filename)
	case "html":
		return r.exportHTML(filename)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func (r *Reporter) exportJSON(filename string) error {
	data, err := json.MarshalIndent(r.Results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (r *Reporter) exportHTML(filename string) error {
	// Print summary to console first
	r.printSummary()

	// Create HTML report
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Cloud Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; }
        .critical { color: red; }
        .high { color: orange; }
        .medium { color: gold; }
        .low { color: blue; }
        .info { color: gray; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Cloud Security Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: %d</p>
        <p><span class="critical">Critical: %d</span></p>
        <p><span class="high">High: %d</span></p>
        <p><span class="medium">Medium: %d</span></p>
        <p><span class="low">Low: %d</span></p>
        <p><span class="info">Info: %d</span></p>
    </div>
    <h2>Findings</h2>
    <table>
        <tr>
            <th>Resource Type</th>
            <th>Resource Name</th>
            <th>Severity</th>
            <th>Issue</th>
            <th>Remediation</th>
        </tr>`

	for _, finding := range r.Results.Findings {
		html += fmt.Sprintf(`
        <tr>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td>%s</td>
            <td>%s</td>
        </tr>`,
			finding.ResourceType,
			finding.ResourceName,
			finding.Severity,
			finding.Severity,
			finding.Issue,
			finding.Remediation,
		)
	}

	html += `
    </table>
</body>
</html>`

	// Format with summary data
	html = fmt.Sprintf(html,
		r.Results.Summary.TotalFindings,
		r.Results.Summary.CriticalCount,
		r.Results.Summary.HighCount,
		r.Results.Summary.MediumCount,
		r.Results.Summary.LowCount,
		r.Results.Summary.InfoCount,
	)

	return os.WriteFile(filename, []byte(html), 0644)
}

func (r *Reporter) printSummary() {
	fmt.Println()
	fmt.Println("📊 Scan Summary")
	fmt.Println("===============")
	fmt.Printf("Total Findings: %d\n", r.Results.Summary.TotalFindings)
	fmt.Printf("  CRITICAL: %d\n", r.Results.Summary.CriticalCount)
	fmt.Printf("  HIGH:     %d\n", r.Results.Summary.HighCount)
	fmt.Printf("  MEDIUM:   %d\n", r.Results.Summary.MediumCount)
	fmt.Printf("  LOW:      %d\n", r.Results.Summary.LowCount)
	fmt.Printf("  INFO:     %d\n", r.Results.Summary.InfoCount)

	// Print top findings
	if len(r.Results.Findings) > 0 {
		fmt.Println()
		fmt.Println("🔴 Top Issues:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SEVERITY\tRESOURCE\tISSUE")
		for _, f := range r.Results.Findings[:min(5, len(r.Results.Findings))] {
			fmt.Fprintf(w, "%s\t%s\t%s\n", f.Severity, f.ResourceName, f.Issue)
		}
		w.Flush()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

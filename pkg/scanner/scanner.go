package scanner

import (
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/natedadson/cloud-security-scanner/internal/config"
	"github.com/natedadson/cloud-security-scanner/pkg/aws"
)

type Finding struct {
	ResourceType string                 `json:"resource_type"`
	ResourceName string                 `json:"resource_name"`
	Severity     string                 `json:"severity"`
	Issue        string                 `json:"issue"`
	Remediation  string                 `json:"remediation"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

type ScanResult struct {
	AccountID string    `json:"account_id"`
	Region    string    `json:"region"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

type Summary struct {
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	InfoCount     int `json:"info_count"`
}

type Scanner struct {
	Session *aws.Session
	Config  config.Config
}

func NewScanner(session *aws.Session, cfg config.Config) *Scanner {
	return &Scanner{
		Session: session,
		Config:  cfg,
	}
}

func (s *Scanner) Scan() (*ScanResult, error) {
	fmt.Println("🔍 Starting security scan...")

	var allFindings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Scan IAM
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings := s.scanIAM()
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}()

	// Scan S3
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings := s.scanS3()
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}()

	// Scan EC2
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings := s.scanEC2()
		mu.Lock()
		allFindings = append(allFindings, findings...)
		mu.Unlock()
	}()

	wg.Wait()

	summary := s.generateSummary(allFindings)

	return &ScanResult{
		AccountID: "622411523600",
		Region:    s.Config.Region,
		Findings:  allFindings,
		Summary:   summary,
	}, nil
}

func (s *Scanner) scanIAM() []Finding {
	fmt.Println("  📋 Scanning IAM...")
	var findings []Finding

	input := &iam.ListRolesInput{}
	err := s.Session.IAM.ListRolesPages(input, func(page *iam.ListRolesOutput, lastPage bool) bool {
		for _, role := range page.Roles {
			finding := Finding{
				ResourceType: "IAM Role",
				ResourceName: *role.RoleName,
				Severity:     "INFO",
				Issue:        "Service account found - review if still needed",
				Remediation:  "Check last used date and remove if unused",
			}
			findings = append(findings, finding)
		}
		return !lastPage
	})

	if err != nil {
		fmt.Printf("    ⚠️ IAM scan error: %v\n", err)
	}

	fmt.Printf("    ✓ Found %d IAM roles\n", len(findings))
	return findings
}

func (s *Scanner) scanS3() []Finding {
	fmt.Println("  📋 Scanning S3...")
	var findings []Finding

	input := &s3.ListBucketsInput{}
	output, err := s.Session.S3.ListBuckets(input)
	if err != nil {
		fmt.Printf("    ⚠️ S3 scan error: %v\n", err)
		return findings
	}

	for _, bucket := range output.Buckets {
		finding := Finding{
			ResourceType: "S3 Bucket",
			ResourceName: *bucket.Name,
			Severity:     "MEDIUM",
			Issue:        "Bucket should be reviewed for public access",
			Remediation:  "Check bucket policy, ACLs, and block public access settings",
		}
		findings = append(findings, finding)
	}

	fmt.Printf("    ✓ Found %d S3 buckets\n", len(findings))
	return findings
}

func (s *Scanner) scanEC2() []Finding {
	fmt.Println("  📋 Scanning EC2...")
	var findings []Finding

	input := &ec2.DescribeInstancesInput{}
	err := s.Session.EC2.DescribeInstancesPages(input, func(page *ec2.DescribeInstancesOutput, lastPage bool) bool {
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.PublicIpAddress != nil {
					finding := Finding{
						ResourceType: "EC2 Instance",
						ResourceName: *instance.InstanceId,
						Severity:     "MEDIUM",
						Issue:        "Instance has public IP address",
						Remediation:  "Consider removing public IP or using VPN",
						Details: map[string]interface{}{
							"public_ip": *instance.PublicIpAddress,
							"state":     *instance.State.Name,
						},
					}
					findings = append(findings, finding)
				}
			}
		}
		return !lastPage
	})

	if err != nil {
		fmt.Printf("    ⚠️ EC2 scan error: %v\n", err)
	}

	fmt.Printf("    ✓ Found %d EC2 instances with public IPs\n", len(findings))
	return findings
}

func (s *Scanner) generateSummary(findings []Finding) Summary {
	summary := Summary{
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			summary.CriticalCount++
		case "HIGH":
			summary.HighCount++
		case "MEDIUM":
			summary.MediumCount++
		case "LOW":
			summary.LowCount++
		case "INFO":
			summary.InfoCount++
		}
	}

	return summary
}

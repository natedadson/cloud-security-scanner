package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/natedadson/cloud-security-scanner/internal/config"
)

type Session struct {
	Session  *session.Session
	IAM      *iam.IAM
	S3       *s3.S3
	EC2      *ec2.EC2
	Config   config.Config
}

func NewSession(cfg config.Config) (*Session, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: cfg.Profile,
		Config: aws.Config{
			Region: aws.String(cfg.Region),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		Session: sess,
		IAM:     iam.New(sess),
		S3:      s3.New(sess),
		EC2:     ec2.New(sess),
		Config:  cfg,
	}, nil
}

func (s *Session) GetAccountID() (string, error) {
	// Get current identity to determine account ID
	return "", nil // Placeholder
}

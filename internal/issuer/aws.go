package issuer

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/shenli/keyradar/internal/secure"
)

// StaticProfile loads ONLY an explicitly selected static profile. No ambient chain,
// credential_process, SSO, web identity, role assumption, or instance metadata is used.
func StaticProfile(ctx context.Context, name string) (*Checker, error) {
	if name == "" {
		return nil, errors.New("explicit static AWS profile required")
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, errors.New("AWS profile unavailable")
	}
	shared, e := config.LoadSharedConfigProfile(ctx, name, func(o *config.LoadSharedConfigOptions) {
		o.ConfigFiles = []string{filepath.Join(home, ".aws", "config")}
		o.CredentialsFiles = []string{filepath.Join(home, ".aws", "credentials")}
	})
	if e != nil || !shared.Credentials.HasKeys() {
		return nil, errors.New("static AWS profile unavailable; helpers and ambient credentials are unsupported")
	}
	return AWSStatic(shared.Credentials.AccessKeyID, shared.Credentials.SecretAccessKey, shared.Credentials.SessionToken), nil
}
func AWSStatic(id, secret, session string) *Checker {
	h := secure.HTTPClient()
	h.Transport = awsTransport{base: h.Transport}
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(id, secret, session), HTTPClient: h, RetryMaxAttempts: 2}
	return WithAWS(iam.NewFromConfig(cfg), sts.NewFromConfig(cfg))
}

type awsTransport struct{ base http.RoundTripper }

func (t awsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || (r.URL.Host != "iam.amazonaws.com" && r.URL.Host != "sts.us-east-1.amazonaws.com") {
		return nil, errors.New("issuer endpoint rejected")
	}
	r.Header.Set("User-Agent", "KeyRadar/0.1.0-alpha")
	return t.base.RoundTrip(r)
}

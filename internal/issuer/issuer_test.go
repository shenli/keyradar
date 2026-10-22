package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/shenli/keyradar/internal/app"
	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/report"
	"github.com/shenli/keyradar/internal/secure"
)

type mockIAM struct {
	last  *time.Time
	err   error
	calls int
}

func (m *mockIAM) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{LastUsedDate: m.last}}, nil
}

type mockSTS struct{ account string }

func (m mockSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(m.account)}, nil
}

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }
func fixture(t *testing.T, provider string) (*model.Case, string) {
	t.Helper()
	c := model.New("custom", time.Now())
	id := c.AddCredential(true, "potentially_exposed")
	account, project, key, kind := "000000000000", "", "AKIA0000000000000000", "iam_access_key"
	if provider == "openai" {
		account = "org_example"
		project = "proj_example"
		key = "key_example"
		kind = "project_api_key"
	}
	if app.Bind(c, id, provider, account, project, key, kind, time.Now()) != nil {
		t.Fatal("fixture bind failed")
	}
	return c, id
}
func TestAWSActivityAndUnknownFreshness(t *testing.T) {
	c, id := fixture(t, "aws")
	last := time.Now().Add(-time.Hour)
	m := &mockIAM{last: &last}
	x := WithAWS(m, mockSTS{"000000000000"})
	if e := x.Check(context.Background(), c, []string{id}, "aws", secure.Token{}); e != nil {
		t.Fatal(e)
	}
	next := last.Add(time.Minute)
	m.last = &next
	if e := x.Check(context.Background(), c, []string{id}, "aws", secure.Token{}); e != nil {
		t.Fatal(e)
	}
	o := c.IssuerObservations[1]
	if o.Reason != "activity_advanced" || o.Freshness != "unknown" || o.Binding != "operator_assertion" {
		t.Fatal("activity semantics")
	}
	for _, t0 := range c.Tasks {
		if t0.Status != "pending" {
			t.Fatal("issuer check completed retirement task")
		}
	}
}
func TestAWSWrongAccountAndNull(t *testing.T) {
	c, id := fixture(t, "aws")
	m := &mockIAM{}
	x := WithAWS(m, mockSTS{"111111111111"})
	x.Check(context.Background(), c, []string{id}, "aws", secure.Token{})
	if m.calls != 0 || c.IssuerObservations[0].Reason != "account_mismatch" {
		t.Fatal("cross-account lookup attempted")
	}
	x.sts = mockSTS{"000000000000"}
	x.Check(context.Background(), c, []string{id}, "aws", secure.Token{})
	if c.IssuerObservations[1].Activity != "insufficient_evidence" {
		t.Fatal("null treated as inactivity")
	}
}
func TestOpenAIResponses(t *testing.T) {
	for _, code := range []int{200, 403, 404, 429, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			c, id := fixture(t, "openai")
			x := New()
			x.client = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "GET" || r.URL.Host != "api.openai.com" || r.URL.Path != "/v1/organization/projects/proj_example/api_keys/key_example" {
					t.Fatal("unexpected request")
				}
				if r.Header.Get("Authorization") != "Bearer AUDIT_CANARY" {
					t.Fatal("audit credential missing")
				}
				body := `{"id":"key_example","object":"organization.project.api_key","last_used_at":null,"redacted_value":"AUDIT_CANARY"}`
				if code != 200 {
					body = `{"error":"AUDIT_CANARY"}`
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			if e := x.Check(context.Background(), c, []string{id}, "openai", secure.NewToken("AUDIT_CANARY")); e != nil {
				t.Fatal(e)
			}
			o := c.IssuerObservations[0]
			if o.Activity != "insufficient_evidence" {
				t.Fatal("null/error established inactivity")
			}
			if code == 404 && o.Reason != "not_found" {
				t.Fatal("missing key misclassified")
			}
			b, _ := json.Marshal(c)
			if strings.Contains(string(b), "AUDIT_CANARY") {
				t.Fatal("audit secret leaked")
			}
			var reportOut strings.Builder
			report.Write(&reportOut, c, "json", true)
			if strings.Contains(reportOut.String(), "org_example") || strings.Contains(reportOut.String(), "key_example") {
				t.Fatal("issuer identifier leaked into shareable report")
			}
		})
	}
}
func TestOpenAIRejectWrongKey(t *testing.T) {
	c, id := fixture(t, "openai")
	x := New()
	x.client = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"other","object":"organization.project.api_key","last_used_at":1}`))}, nil
	})}
	x.Check(context.Background(), c, []string{id}, "openai", secure.NewToken("test"))
	if c.IssuerObservations[0].Reason != "invalid_response" {
		t.Fatal("incorrect key accepted")
	}
}
func TestSDKErrorNeverEscapes(t *testing.T) {
	c, id := fixture(t, "aws")
	x := WithAWS(&mockIAM{err: errors.New("PRIVATE_RESPONSE_CANARY")}, mockSTS{"000000000000"})
	if e := x.Check(context.Background(), c, []string{id}, "aws", secure.Token{}); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "PRIVATE_RESPONSE_CANARY") {
		t.Fatal("SDK error leaked")
	}
}

func TestFutureActivityNeverBecomesUsageEvidence(t *testing.T) {
	c, id := fixture(t, "aws")
	future := time.Now().Add(time.Hour)
	x := WithAWS(&mockIAM{last: &future}, mockSTS{"000000000000"})
	if err := x.Check(context.Background(), c, []string{id}, "aws", secure.Token{}); err != nil {
		t.Fatal(err)
	}
	o := c.IssuerObservations[0]
	if o.LastUsedAt != nil || o.Activity != "insufficient_evidence" || o.Reason != "invalid_response" {
		t.Fatal("future timestamp trusted")
	}
}

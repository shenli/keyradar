// Package issuer collects read-only evidence using independent audit authorization.
package issuer

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
)

type IAM interface {
	GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
}
type STS interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}
type Checker struct {
	client *http.Client
	now    func() time.Time
	iam    IAM
	sts    STS
}

func New() *Checker                 { return &Checker{client: secure.HTTPClient(), now: time.Now} }
func WithAWS(i IAM, s STS) *Checker { c := New(); c.iam = i; c.sts = s; return c }

var awsKey = regexp.MustCompile(`^AKIA[A-Z0-9]{16}$`)
var account = regexp.MustCompile(`^[0-9]{12}$`)
var openID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (x *Checker) Check(ctx context.Context, c *model.Case, ids []string, provider string, token secure.Token) error {
	if !model.In(provider, "aws", "openai") || len(ids) == 0 || len(ids) > 100 {
		return errors.New("select an issuer and 1 to 100 credential IDs")
	}
	for _, id := range ids {
		if c.Credential(id) == nil {
			return errors.New("credential ID not found")
		}
	}
	c.ToolAccess = append(c.ToolAccess, model.ToolAccess{ID: model.ID("auth"), Provider: provider, StartedAt: x.now().UTC(), Cleanup: "pending"})
	c.AddTask("", "", "cleanup_tool_access")
	for _, id := range ids {
		cr := c.Credential(id)
		o := model.IssuerObservation{ID: model.ID("evidence"), CredentialID: id, Issuer: provider, Source: "issuer_api", FetchedAt: x.now().UTC(), Status: "partial", Reason: "binding_required", Activity: "insufficient_evidence", Freshness: "unknown", Binding: cr.Binding, Account: cr.Account, Project: cr.Project, KeyID: cr.KeyID}
		if cr.Issuer == provider && cr.Binding != "unknown" {
			if ctx.Err() != nil {
				o.Reason = "cancelled"
			} else if provider == "aws" {
				x.aws(ctx, *cr, &o)
			} else {
				x.openai(ctx, *cr, token, &o)
			}
		}
		if o.LastUsedAt != nil {
			o.Activity = "usage_observed"
			if o.LastUsedAt.After(o.FetchedAt.Add(time.Minute)) {
				o.LastUsedAt = nil
				o.Activity = "insufficient_evidence"
				o.Status = "partial"
				o.Reason = "invalid_response"
			} else {
				for j := len(c.IssuerObservations) - 1; j >= 0; j-- {
					p := c.IssuerObservations[j]
					if p.CredentialID == id && p.Issuer == provider && p.KeyID == o.KeyID && p.Account == o.Account && p.Project == o.Project && p.LastUsedAt != nil {
						if o.LastUsedAt.After(*p.LastUsedAt) {
							o.Reason = "activity_advanced"
						}
						break
					}
				}
			}
		}
		c.IssuerObservations = append(c.IssuerObservations, o)
	}
	c.UpdatedAt = x.now().UTC()
	c.Disposition = "open"
	return c.Validate()
}
func apiReason(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	var e smithy.APIError
	if errors.As(err, &e) {
		switch e.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "InvalidClientTokenId":
			return "permission_denied"
		case "NoSuchEntity", "NoSuchEntityException":
			return "not_found"
		case "Throttling", "ThrottlingException", "TooManyRequestsException":
			return "rate_limited"
		}
	}
	return "request_failed"
}
func (x *Checker) aws(ctx context.Context, cr model.Credential, o *model.IssuerObservation) {
	if cr.Kind != "iam_access_key" || !awsKey.MatchString(cr.KeyID) {
		o.Reason = "unsupported_key_class"
		o.Status = "unsupported"
		return
	}
	if !account.MatchString(cr.Account) || x.iam == nil || x.sts == nil {
		o.Reason = "binding_required"
		return
	}
	who, e := x.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if e != nil {
		o.Reason = apiReason(e)
		return
	}
	if who == nil || aws.ToString(who.Account) != cr.Account {
		o.Reason = "account_mismatch"
		return
	}
	out, e := x.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(cr.KeyID)})
	if e != nil {
		o.Reason = apiReason(e)
		return
	}
	// The successful lookup still does not establish equality to a local configuration value.
	if out == nil {
		o.Reason = "invalid_response"
		return
	}
	o.Status = "complete"
	o.Reason = "null_activity"
	if out != nil && out.AccessKeyLastUsed != nil {
		o.LastUsedAt = out.AccessKeyLastUsed.LastUsedDate
		if o.LastUsedAt != nil {
			o.Reason = "freshness_unknown"
		}
	}
}
func (x *Checker) openai(ctx context.Context, cr model.Credential, t secure.Token, o *model.IssuerObservation) {
	if cr.Kind != "project_api_key" || !openID.MatchString(cr.Project) || !openID.MatchString(cr.KeyID) || !openID.MatchString(cr.Account) {
		o.Reason = "binding_required"
		return
	}
	if t.Reveal() == "" {
		o.Status = "permission_denied"
		o.Reason = "permission_denied"
		return
	}
	endpoint := "https://api.openai.com/v1/organization/projects/" + url.PathEscape(cr.Project) + "/api_keys/" + url.PathEscape(cr.KeyID)
	req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if e != nil {
		o.Reason = "request_failed"
		return
	}
	req.Header.Set("Authorization", "Bearer "+t.Reveal())
	req.Header.Set("OpenAI-Organization", cr.Account)
	req.Header.Set("User-Agent", "KeyRadar/"+model.Version+" "+o.ID)
	resp, e := x.client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			o.Reason = "cancelled"
		} else {
			o.Reason = "request_failed"
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		switch resp.StatusCode {
		case 401, 403:
			o.Status = "permission_denied"
			o.Reason = "permission_denied"
		case 404:
			o.Reason = "not_found"
		case 429:
			o.Status = "rate_limited"
			o.Reason = "rate_limited"
		default:
			o.Reason = "request_failed"
		}
		return
	}
	var out struct {
		ID         string `json:"id"`
		Object     string `json:"object"`
		LastUsedAt *int64 `json:"last_used_at"`
	}
	if secure.Decode(resp.Body, 1<<20, &out) != nil || out.ID != cr.KeyID || out.Object != "organization.project.api_key" {
		o.Reason = "invalid_response"
		return
	}
	o.Status = "complete"
	o.Reason = "null_activity"
	if out.LastUsedAt != nil && *out.LastUsedAt < 0 {
		o.Status = "partial"
		o.Reason = "invalid_response"
		return
	}
	if out.LastUsedAt != nil && *out.LastUsedAt > 0 {
		tm := time.Unix(*out.LastUsedAt, 0).UTC()
		o.LastUsedAt = &tm
		o.Reason = "freshness_unknown"
	}
}

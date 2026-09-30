package kicktemp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gtm-mcp-server/auth"

	"golang.org/x/oauth2"
)

const testClientID = "client-123.apps.googleusercontent.com"

func idToken(claims map[string]any) *oauth2.Token {
	b, _ := json.Marshal(claims)
	jwt := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	return (&oauth2.Token{AccessToken: "g"}).WithExtra(map[string]any{"id_token": jwt})
}

func goodClaims(email string) map[string]any {
	return map[string]any{
		"iss": "https://accounts.google.com", "aud": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(), "email": email, "email_verified": true,
	}
}

func newPolicy() *EmailPolicy {
	return NewEmailPolicy(&Config{AllowedEmails: []string{"niels@kicktemp.com", "team@kicktemp.com"}}, testClientID)
}

func TestVerifyAllowsListedAccounts(t *testing.T) {
	p := newPolicy()
	for _, in := range []string{"niels@kicktemp.com", "Niels@Kicktemp.com", " team@kicktemp.com"} {
		got, err := p.Verify(context.Background(), idToken(goodClaims(in)))
		if err != nil || got != strings.ToLower(strings.TrimSpace(in)) {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
}

func TestVerifyRefuses(t *testing.T) {
	mod := func(email string, f func(m map[string]any)) *oauth2.Token {
		m := goodClaims(email)
		f(m)
		return idToken(m)
	}
	cases := map[string]*oauth2.Token{
		"account not on the list": idToken(goodClaims("someone@gmail.com")),
		"lookalike domain":        idToken(goodClaims("niels@kicktemp.com.evil.io")),
		"unverified email":        mod("niels@kicktemp.com", func(m map[string]any) { m["email_verified"] = false }),
		"missing email_verified":  mod("niels@kicktemp.com", func(m map[string]any) { delete(m, "email_verified") }),
		"other OAuth client":      mod("niels@kicktemp.com", func(m map[string]any) { m["aud"] = "other" }),
		"wrong issuer":            mod("niels@kicktemp.com", func(m map[string]any) { m["iss"] = "https://evil.example" }),
		"expired":                 mod("niels@kicktemp.com", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no id_token":             {AccessToken: "g"},
		"malformed id_token":      (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "not-a-jwt"}),
		"undecodable payload":     (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "a.!!!.c"}),
	}
	for name, tok := range cases {
		if got, err := newPolicy().Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: must be refused, got %q", name, got)
		}
	}
	// An empty allowlist refuses everyone.
	if _, err := NewEmailPolicy(&Config{}, testClientID).Verify(context.Background(), idToken(goodClaims("niels@kicktemp.com"))); err == nil {
		t.Error("empty KT_ALLOWED_EMAILS must refuse every login")
	}
}

func TestCheckRequest(t *testing.T) {
	p := newPolicy()
	withInfo := func(email string) context.Context {
		return context.WithValue(context.Background(), auth.TokenInfoKey, &auth.TokenInfo{AccessToken: "x", Email: email})
	}
	if err := p.checkRequest(withInfo("niels@kicktemp.com")); err != nil {
		t.Errorf("allowed account refused: %v", err)
	}
	if err := p.checkRequest(withInfo("removed@kicktemp.com")); err == nil {
		t.Error("account removed from the list must be refused on the next request")
	}
	if err := p.checkRequest(withInfo("")); err == nil {
		t.Error("token without a verified email must be refused")
	}
	if err := p.checkRequest(context.Background()); err == nil {
		t.Error("request without any identity must be refused")
	}
	sa := context.WithValue(context.Background(), auth.SATokenSourceKey, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "g"}))
	if err := p.checkRequest(sa); err != nil {
		t.Errorf("service-account bearer key is not an OAuth identity: %v", err)
	}
	var none *EmailPolicy
	if err := none.checkRequest(context.Background()); err != nil {
		t.Errorf("nil policy (OAuth off) must not check: %v", err)
	}
}

func TestIdentityScopesAndEmailConfig(t *testing.T) {
	in := []string{"a"}
	out := IdentityScopes(in)
	if strings.Join(out, ",") != "a,openid,email" || len(in) != 1 {
		t.Errorf("scopes %v (input mutated: %v)", out, in)
	}
	if again := IdentityScopes(out); len(again) != 3 {
		t.Errorf("must not duplicate: %v", again)
	}
	get := func(v string) func(string) string {
		return func(k string) string {
			if k == "KT_ALLOWED_EMAILS" {
				return v
			}
			return ""
		}
	}
	c, err := Load(get(" Niels@Kicktemp.com, a@b.de ,,"))
	if err != nil || strings.Join(c.AllowedEmails, "|") != "niels@kicktemp.com|a@b.de" {
		t.Fatalf("emails: %v %v", c, err)
	}
	for _, bad := range []string{"notanemail", "*@kicktemp.com", "a b@c.de"} {
		if _, err := Load(get(bad)); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

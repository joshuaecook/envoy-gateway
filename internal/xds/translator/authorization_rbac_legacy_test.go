// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"strings"
	"testing"

	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	mtlsauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoymatcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
)

// ---- fixtures ----

// sanAuthorization builds a minimal single-rule Authorization matching on the supplied
// clientCert principal, with the only rule/default action pair the legacy lowering
// accepts.
func sanAuthorization(clientCert *egv1a1.ClientCertPrincipal) *ir.Authorization {
	return &ir.Authorization{
		DefaultAction: egv1a1.AuthorizationActionDeny,
		Rules: []*ir.AuthorizationRule{
			{
				Name:      "rule-0",
				Action:    egv1a1.AuthorizationActionAllow,
				Principal: ir.Principal{ClientCert: clientCert},
			},
		},
	}
}

func uriSAN(values ...string) *egv1a1.ClientCertPrincipal {
	uris := make([]egv1a1.StringMatch, 0, len(values))
	for _, v := range values {
		uris = append(uris, egv1a1.StringMatch{Type: ptr.To(egv1a1.StringMatchExact), Value: v})
	}
	return &egv1a1.ClientCertPrincipal{
		SubjectAltNames: &egv1a1.SubjectAltNames{URIs: uris},
	}
}

// ---- helpers ----

// onlyPolicy returns the single policy of a legacy RBAC config, failing if there is not
// exactly one.
func onlyPolicy(t *testing.T, perRoute *rbacconfigv3.RBAC) *rbacconfigv3.Policy {
	t.Helper()
	require.Len(t, perRoute.Policies, 1)
	for _, policy := range perRoute.Policies {
		return policy
	}
	return nil
}

// mtlsConfigOf asserts that a principal is an mtls_authenticated custom principal and
// returns its decoded config.
func mtlsConfigOf(t *testing.T, principal *rbacconfigv3.Principal) *mtlsauthnv3.Config {
	t.Helper()
	custom, ok := principal.Identifier.(*rbacconfigv3.Principal_Custom)
	require.True(t, ok, "expected a custom (extension) principal, got %T", principal.Identifier)
	require.Equal(t, "envoy.rbac.principals.mtls_authenticated", custom.Custom.Name)

	cfg := &mtlsauthnv3.Config{}
	require.NoError(t, custom.Custom.TypedConfig.UnmarshalTo(cfg))
	return cfg
}

func orIDsOf(t *testing.T, principal *rbacconfigv3.Principal) []*rbacconfigv3.Principal {
	t.Helper()
	or, ok := principal.Identifier.(*rbacconfigv3.Principal_OrIds)
	require.True(t, ok, "expected an or_ids principal, got %T", principal.Identifier)
	return or.OrIds.Ids
}

func andIDsOf(t *testing.T, principal *rbacconfigv3.Principal) []*rbacconfigv3.Principal {
	t.Helper()
	and, ok := principal.Identifier.(*rbacconfigv3.Principal_AndIds)
	require.True(t, ok, "expected an and_ids principal, got %T", principal.Identifier)
	return and.AndIds.Ids
}

// ---- mode selection ----

func TestBuildRBACPerRouteForAuthorization_SANsUseLegacyRulesAPI(t *testing.T) {
	// The two RBAC APIs are mutually exclusive per filter instance ("When both rules and
	// matcher are configured, rules will be ignored"), so a SAN-matching Authorization
	// must produce rules and NO matcher.
	perRoute, err := buildRBACPerRouteForAuthorization(sanAuthorization(uriSAN("spiffe://x/allowed")))
	require.NoError(t, err)
	require.NotNil(t, perRoute.Rbac.Rules, "SAN matching must be lowered to the legacy rules API")
	require.Nil(t, perRoute.Rbac.Matcher, "the matcher API must not be populated alongside rules")
}

func TestBuildRBACPerRouteForAuthorization_SubjectOnlyKeepsMatcherAPI(t *testing.T) {
	// A subject-only policy must keep working exactly as it does today, on the matcher
	// API.
	authorization := sanAuthorization(&egv1a1.ClientCertPrincipal{
		Subject: &egv1a1.StringMatch{Value: "CN=client.example.com"},
	})
	perRoute, err := buildRBACPerRouteForAuthorization(authorization)
	require.NoError(t, err)
	require.Nil(t, perRoute.Rbac.Rules, "subject-only matching must not switch to the legacy API")
	require.NotNil(t, perRoute.Rbac.Matcher)
}

func TestBuildRBACPerRouteForAuthorization_NoClientCertKeepsMatcherAPI(t *testing.T) {
	authorization := &ir.Authorization{
		DefaultAction: egv1a1.AuthorizationActionDeny,
		Rules: []*ir.AuthorizationRule{
			{
				Name:   "rule-0",
				Action: egv1a1.AuthorizationActionAllow,
				Principal: ir.Principal{
					Headers: []egv1a1.AuthorizationHeaderMatch{{Name: "x-user", Values: []string{"alice"}}},
				},
			},
		},
	}
	perRoute, err := buildRBACPerRouteForAuthorization(authorization)
	require.NoError(t, err)
	require.Nil(t, perRoute.Rbac.Rules)
	require.NotNil(t, perRoute.Rbac.Matcher)
}

// ---- SAN principals ----

// TestBuildRBACPerRouteLegacy_URISANIsNotStringMatchedAgainstAJoinedInput is the direct
// regression for the forgeable lowering this replaces. Envoy joins every URI SAN into
// one comma-separated string for the uri_san matcher input, so a certificate with the
// single SAN "a,b" is indistinguishable there from one with the SANs "a" and "b". The
// replacement must not reach that input at all: the value has to travel as an
// unmodified Exact matcher inside an mtls_authenticated SubjectAltNameMatcher, which
// Envoy applies to each SAN separately.
func TestBuildRBACPerRouteLegacy_URISANIsNotStringMatchedAgainstAJoinedInput(t *testing.T) {
	const allowed = "spiffe://x/allowed"

	perRoute, err := buildRBACPerRouteLegacy(sanAuthorization(uriSAN(allowed)))
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	require.Len(t, policy.Principals, 1)

	cfg := mtlsConfigOf(t, policy.Principals[0])
	require.NotNil(t, cfg.SanMatcher, "san_matcher must be set; the extension rejects a config with neither field")
	require.False(t, cfg.AnyValidatedClientCertificate)
	require.Equal(t, tlsv3.SubjectAltNameMatcher_URI, cfg.SanMatcher.SanType)

	exact, ok := cfg.SanMatcher.Matcher.MatchPattern.(*envoymatcherv3.StringMatcher_Exact)
	require.True(t, ok, "an Exact EG match must stay an Exact string matcher, not become a regex, got %T",
		cfg.SanMatcher.Matcher.MatchPattern)
	require.Equal(t, allowed, exact.Exact, "the policy value must be passed through byte for byte")
}

func TestBuildRBACPerRouteLegacy_DNSSANUsesDNSSanType(t *testing.T) {
	clientCert := &egv1a1.ClientCertPrincipal{
		SubjectAltNames: &egv1a1.SubjectAltNames{
			DNSNames: []egv1a1.StringMatch{{Value: "svc.example.com"}},
		},
	}
	perRoute, err := buildRBACPerRouteLegacy(sanAuthorization(clientCert))
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	cfg := mtlsConfigOf(t, policy.Principals[0])
	require.Equal(t, tlsv3.SubjectAltNameMatcher_DNS, cfg.SanMatcher.SanType)
}

func TestBuildRBACPerRouteLegacy_AllStringMatchTypesRemainExpressible(t *testing.T) {
	// SubjectAltNameMatcher takes a full StringMatcher, so no match type has to be
	// dropped or rewritten into a regex to make SAN matching safe.
	cases := []struct {
		desc   string
		match  egv1a1.StringMatch
		assert func(t *testing.T, m *envoymatcherv3.StringMatcher)
	}{
		{
			desc:  "nil type defaults to exact",
			match: egv1a1.StringMatch{Value: "spiffe://x/a"},
			assert: func(t *testing.T, m *envoymatcherv3.StringMatcher) {
				p, ok := m.MatchPattern.(*envoymatcherv3.StringMatcher_Exact)
				require.True(t, ok, "got %T", m.MatchPattern)
				require.Equal(t, "spiffe://x/a", p.Exact)
			},
		},
		{
			desc:  "prefix",
			match: egv1a1.StringMatch{Type: ptr.To(egv1a1.StringMatchPrefix), Value: "spiffe://x/"},
			assert: func(t *testing.T, m *envoymatcherv3.StringMatcher) {
				p, ok := m.MatchPattern.(*envoymatcherv3.StringMatcher_Prefix)
				require.True(t, ok, "got %T", m.MatchPattern)
				require.Equal(t, "spiffe://x/", p.Prefix)
			},
		},
		{
			desc:  "suffix",
			match: egv1a1.StringMatch{Type: ptr.To(egv1a1.StringMatchSuffix), Value: "/sa/client"},
			assert: func(t *testing.T, m *envoymatcherv3.StringMatcher) {
				p, ok := m.MatchPattern.(*envoymatcherv3.StringMatcher_Suffix)
				require.True(t, ok, "got %T", m.MatchPattern)
				require.Equal(t, "/sa/client", p.Suffix)
			},
		},
		{
			desc:  "regular expression is passed through with the re2 engine",
			match: egv1a1.StringMatch{Type: ptr.To(egv1a1.StringMatchRegularExpression), Value: `^spiffe://x/.*$`},
			assert: func(t *testing.T, m *envoymatcherv3.StringMatcher) {
				p, ok := m.MatchPattern.(*envoymatcherv3.StringMatcher_SafeRegex)
				require.True(t, ok, "got %T", m.MatchPattern)
				require.Equal(t, `^spiffe://x/.*$`, p.SafeRegex.Regex)
				engine, ok := p.SafeRegex.EngineType.(*envoymatcherv3.RegexMatcher_GoogleRe2)
				require.True(t, ok, "got %T", p.SafeRegex.EngineType)
				require.NotNil(t, engine.GoogleRe2)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			clientCert := &egv1a1.ClientCertPrincipal{
				SubjectAltNames: &egv1a1.SubjectAltNames{URIs: []egv1a1.StringMatch{tc.match}},
			}
			perRoute, err := buildRBACPerRouteLegacy(sanAuthorization(clientCert))
			require.NoError(t, err)
			cfg := mtlsConfigOf(t, onlyPolicy(t, perRoute.Rbac.Rules).Principals[0])
			require.NotContains(t, cfg.SanMatcher.Matcher.String(), ",",
				"no comma-boundary encoding may appear in the emitted matcher")
			tc.assert(t, cfg.SanMatcher.Matcher)
		})
	}
}

func TestBuildRBACPerRouteLegacy_MultipleSANsOrCombine(t *testing.T) {
	clientCert := &egv1a1.ClientCertPrincipal{
		SubjectAltNames: &egv1a1.SubjectAltNames{
			URIs:     []egv1a1.StringMatch{{Value: "spiffe://x/a"}, {Value: "spiffe://x/b"}},
			DNSNames: []egv1a1.StringMatch{{Value: "svc.example.com"}},
		},
	}
	perRoute, err := buildRBACPerRouteLegacy(sanAuthorization(clientCert))
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	require.Len(t, policy.Principals, 1)

	ids := orIDsOf(t, policy.Principals[0])
	require.Len(t, ids, 3, "every uris and dnsNames entry OR-combines into one group")

	sanTypes := make([]tlsv3.SubjectAltNameMatcher_SanType, 0, len(ids))
	for _, id := range ids {
		sanTypes = append(sanTypes, mtlsConfigOf(t, id).SanMatcher.SanType)
	}
	require.ElementsMatch(t, []tlsv3.SubjectAltNameMatcher_SanType{
		tlsv3.SubjectAltNameMatcher_URI,
		tlsv3.SubjectAltNameMatcher_URI,
		tlsv3.SubjectAltNameMatcher_DNS,
	}, sanTypes)
}

func TestBuildRBACPerRouteLegacy_UnsupportedSANTypesRejected(t *testing.T) {
	for _, tc := range []struct {
		desc string
		san  *egv1a1.SubjectAltNames
	}{
		{"emailAddresses", &egv1a1.SubjectAltNames{EmailAddresses: []egv1a1.StringMatch{{Value: "a@b.c"}}}},
		{"ipAddresses", &egv1a1.SubjectAltNames{IPAddresses: []egv1a1.StringMatch{{Value: "10.0.0.1"}}}},
		{"otherNames", &egv1a1.SubjectAltNames{OtherNames: []egv1a1.OtherSANMatch{{Oid: "1.2.3"}}}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := buildRBACPerRouteLegacy(sanAuthorization(&egv1a1.ClientCertPrincipal{SubjectAltNames: tc.san}))
			require.Error(t, err)
			require.Contains(t, err.Error(), "uris and dnsNames")
		})
	}
}

func TestBuildRBACPerRouteLegacy_EmptySANGroupRejected(t *testing.T) {
	// A subjectAltNames block contributing no certificate predicate would let a rule
	// authorize on its other conditions alone.
	_, err := buildRBACPerRouteLegacy(sanAuthorization(&egv1a1.ClientCertPrincipal{
		SubjectAltNames: &egv1a1.SubjectAltNames{},
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one entry")
}

// ---- conditions the legacy API cannot express ----

func TestBuildRBACPerRouteLegacy_SubjectWithSANsRejected(t *testing.T) {
	// Legacy RBAC has no correct Subject DN principal.
	// Principal.authenticated.principal_name consults the subject field only when the
	// certificate has neither a URI nor a DNS SAN, so it is not one.
	_, err := buildRBACPerRouteLegacy(sanAuthorization(&egv1a1.ClientCertPrincipal{
		Subject:         &egv1a1.StringMatch{Value: "CN=client"},
		SubjectAltNames: &egv1a1.SubjectAltNames{URIs: []egv1a1.StringMatch{{Value: "spiffe://x/a"}}},
	}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "clientCert.subject")
	require.Contains(t, err.Error(), "clientCert.subjectAltNames")
}

func TestBuildRBACPerRouteLegacy_CELWithSANsRejected(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].CEL = ptr.To("request.method == 'POST'")
	_, err := buildRBACPerRouteLegacy(authorization)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cel")
	require.Contains(t, err.Error(), "clientCert.subjectAltNames")
}

func TestBuildRBACPerRouteLegacy_ActionMapping(t *testing.T) {
	cases := []struct {
		desc          string
		ruleAction    egv1a1.AuthorizationAction
		defaultAction egv1a1.AuthorizationAction
		want          rbacconfigv3.RBAC_Action
		wantErr       bool
	}{
		{"allow rules with deny default", egv1a1.AuthorizationActionAllow, egv1a1.AuthorizationActionDeny, rbacconfigv3.RBAC_ALLOW, false},
		{"deny rules with allow default", egv1a1.AuthorizationActionDeny, egv1a1.AuthorizationActionAllow, rbacconfigv3.RBAC_DENY, false},
		// Legacy RBAC always takes the opposite action for a request matching no policy,
		// so a default action equal to the rule action has no encoding.
		{"allow rules with allow default", egv1a1.AuthorizationActionAllow, egv1a1.AuthorizationActionAllow, rbacconfigv3.RBAC_ALLOW, true},
		{"deny rules with deny default", egv1a1.AuthorizationActionDeny, egv1a1.AuthorizationActionDeny, rbacconfigv3.RBAC_DENY, true},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			authorization := sanAuthorization(uriSAN("spiffe://x/a"))
			authorization.Rules[0].Action = tc.ruleAction
			authorization.DefaultAction = tc.defaultAction

			perRoute, err := buildRBACPerRouteLegacy(authorization)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "defaultAction")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, perRoute.Rbac.Rules.Action)
		})
	}
}

func TestBuildRBACPerRouteLegacy_MixedRuleActionsRejected(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules = append(authorization.Rules, &ir.AuthorizationRule{
		Name:      "rule-1",
		Action:    egv1a1.AuthorizationActionDeny,
		Principal: ir.Principal{ClientCert: uriSAN("spiffe://x/b")},
	})
	_, err := buildRBACPerRouteLegacy(authorization)
	require.Error(t, err)
	require.Contains(t, err.Error(), "same action")
}

func TestBuildRBACPerRouteLegacy_DuplicateRuleNamesRejected(t *testing.T) {
	// Legacy policies is a map keyed by rule name; a collision would silently drop a
	// rule.
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules = append(authorization.Rules, &ir.AuthorizationRule{
		Name:      "rule-0",
		Action:    egv1a1.AuthorizationActionAllow,
		Principal: ir.Principal{ClientCert: uriSAN("spiffe://x/b")},
	})
	_, err := buildRBACPerRouteLegacy(authorization)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

// ---- other principal and operation types on the legacy path ----

func TestBuildRBACPerRouteLegacy_NoOperationMatchesAnyRequest(t *testing.T) {
	perRoute, err := buildRBACPerRouteLegacy(sanAuthorization(uriSAN("spiffe://x/a")))
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	require.Len(t, policy.Permissions, 1)
	any, ok := policy.Permissions[0].Rule.(*rbacconfigv3.Permission_Any)
	require.True(t, ok, "got %T", policy.Permissions[0].Rule)
	require.True(t, any.Any)
}

func TestBuildRBACPerRouteLegacy_OperationMethodsAndPath(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Operation = &egv1a1.Operation{
		Methods: []gwapiv1.HTTPMethod{gwapiv1.HTTPMethodGet, gwapiv1.HTTPMethodPost},
		Path:    &egv1a1.PathMatch{Type: ptr.To(gwapiv1.PathMatchExact), Value: "/admin"},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	require.Len(t, policy.Permissions, 1)

	and, ok := policy.Permissions[0].Rule.(*rbacconfigv3.Permission_AndRules)
	require.True(t, ok, "methods and path AND-combine, got %T", policy.Permissions[0].Rule)
	require.Len(t, and.AndRules.Rules, 2)

	// Methods OR-combine under the first rule.
	or, ok := and.AndRules.Rules[0].Rule.(*rbacconfigv3.Permission_OrRules)
	require.True(t, ok, "got %T", and.AndRules.Rules[0].Rule)
	require.Len(t, or.OrRules.Rules, 2)
	for _, r := range or.OrRules.Rules {
		header, ok := r.Rule.(*rbacconfigv3.Permission_Header)
		require.True(t, ok, "got %T", r.Rule)
		require.Equal(t, ":method", header.Header.Name)
	}

	// Path lowers to a :path header matcher, matching the same value the matcher API
	// path matches (Permission.url_path would strip the query string).
	pathRule, ok := and.AndRules.Rules[1].Rule.(*rbacconfigv3.Permission_Header)
	require.True(t, ok, "got %T", and.AndRules.Rules[1].Rule)
	require.Equal(t, ":path", pathRule.Header.Name)
	require.False(t, pathRule.Header.InvertMatch)
}

func TestBuildRBACPerRouteLegacy_InvertedPathUsesHeaderInvert(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Operation = &egv1a1.Operation{
		Path: &egv1a1.PathMatch{Type: ptr.To(gwapiv1.PathMatchExact), Value: "/admin", Invert: ptr.To(true)},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	permission := onlyPolicy(t, perRoute.Rbac.Rules).Permissions[0]
	header, ok := permission.Rule.(*rbacconfigv3.Permission_Header)
	require.True(t, ok, "got %T", permission.Rule)
	require.True(t, header.Header.InvertMatch)
}

func TestBuildRBACPerRouteLegacy_ClientCIDRsAndSANsAndCombine(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Principal.ClientCIDRs = []*ir.CIDRMatch{{CIDR: "10.0.0.0/8", MaskLen: 8}}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	policy := onlyPolicy(t, perRoute.Rbac.Rules)
	require.Len(t, policy.Principals, 1, "a legacy policy's principals list is OR-combined, so AND must be expressed inside one entry")

	ids := andIDsOf(t, policy.Principals[0])
	require.Len(t, ids, 2)

	remoteIP, ok := ids[0].Identifier.(*rbacconfigv3.Principal_RemoteIp)
	require.True(t, ok, "got %T", ids[0].Identifier)
	require.Equal(t, "10.0.0.0", remoteIP.RemoteIp.AddressPrefix)
	require.Equal(t, uint32(8), remoteIP.RemoteIp.PrefixLen.GetValue())

	mtlsConfigOf(t, ids[1])
}

func TestBuildRBACPerRouteLegacy_HeaderValuesOrCombine(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Principal.Headers = []egv1a1.AuthorizationHeaderMatch{
		{Name: "x-user", Values: []string{"alice", "bob"}},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	ids := andIDsOf(t, onlyPolicy(t, perRoute.Rbac.Rules).Principals[0])
	require.Len(t, ids, 2)

	values := orIDsOf(t, ids[0])
	require.Len(t, values, 2)
	got := make([]string, 0, 2)
	for _, id := range values {
		header, ok := id.Identifier.(*rbacconfigv3.Principal_Header)
		require.True(t, ok, "got %T", id.Identifier)
		require.Equal(t, "x-user", header.Header.Name)
		got = append(got, headerExactValue(t, header.Header))
	}
	require.ElementsMatch(t, []string{"alice", "bob"}, got)
}

func TestBuildRBACPerRouteLegacy_JWTClaimUsesMetadataPrincipal(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Principal.JWT = &egv1a1.JWTPrincipal{
		Provider: "example",
		Claims:   []egv1a1.JWTClaim{{Name: "organization.department", Values: []string{"eng"}}},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	ids := andIDsOf(t, onlyPolicy(t, perRoute.Rbac.Rules).Principals[0])
	require.Len(t, ids, 2)

	metadata, ok := ids[0].Identifier.(*rbacconfigv3.Principal_Metadata)
	require.True(t, ok, "got %T", ids[0].Identifier)
	require.Equal(t, "envoy.filters.http.jwt_authn", metadata.Metadata.Filter)

	keys := make([]string, 0, len(metadata.Metadata.Path))
	for _, segment := range metadata.Metadata.Path {
		keys = append(keys, segment.GetKey())
	}
	require.Equal(t, []string{"example", "organization", "department"}, keys,
		"a dotted claim name expands to one path segment per component")
}

func TestBuildRBACPerRouteLegacy_JWTScopeChecksBothScopeKeys(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Principal.JWT = &egv1a1.JWTPrincipal{
		Provider: "example",
		Scopes:   []egv1a1.JWTScope{"read"},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	ids := andIDsOf(t, onlyPolicy(t, perRoute.Rbac.Rules).Principals[0])
	scopeIDs := orIDsOf(t, ids[0])
	require.Len(t, scopeIDs, 2)

	lastKeys := make([]string, 0, 2)
	for _, id := range scopeIDs {
		metadata, ok := id.Identifier.(*rbacconfigv3.Principal_Metadata)
		require.True(t, ok, "got %T", id.Identifier)
		path := metadata.Metadata.Path
		lastKeys = append(lastKeys, path[len(path)-1].GetKey())
	}
	require.ElementsMatch(t, []string{"scope", "scp"}, lastKeys)
}

func TestBuildRBACPerRouteLegacy_GeoIPUsesInternalHeaders(t *testing.T) {
	authorization := sanAuthorization(uriSAN("spiffe://x/a"))
	authorization.Rules[0].Principal.ClientIPGeoLocations = []egv1a1.ClientIPGeoLocation{
		{Country: ptr.To("US"), City: ptr.To("Cupertino")},
	}

	perRoute, err := buildRBACPerRouteLegacy(authorization)
	require.NoError(t, err)

	ids := andIDsOf(t, onlyPolicy(t, perRoute.Rbac.Rules).Principals[0])
	require.Len(t, ids, 2)

	fields := andIDsOf(t, ids[0])
	require.Len(t, fields, 2, "fields within one location AND-combine")
	for _, field := range fields {
		header, ok := field.Identifier.(*rbacconfigv3.Principal_Header)
		require.True(t, ok, "got %T", field.Identifier)
		require.True(t, strings.HasPrefix(header.Header.Name, "x-eg-internal-geoip-"),
			"expected an internal GeoIP header, got %q", header.Header.Name)
	}
}

func headerExactValue(t *testing.T, matcher *routev3.HeaderMatcher) string {
	t.Helper()
	stringMatch, ok := matcher.HeaderMatchSpecifier.(*routev3.HeaderMatcher_StringMatch)
	require.True(t, ok, "got %T", matcher.HeaderMatchSpecifier)
	exact, ok := stringMatch.StringMatch.MatchPattern.(*envoymatcherv3.StringMatcher_Exact)
	require.True(t, ok, "got %T", stringMatch.StringMatch.MatchPattern)
	return exact.Exact
}

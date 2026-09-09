// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	configv3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbacconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	mtlsauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rbac/principals/mtls_authenticated/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoymatcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/ir"
	"github.com/envoyproxy/gateway/internal/utils/proto"
	"github.com/envoyproxy/gateway/internal/utils/regex"
)

// mtlsAuthenticatedPrincipalName is the name of the RBAC principal extension that
// evaluates the validated peer certificate's SANs individually.
//
// The extension is listed in Envoy's source/extensions/extensions_build_config.bzl, so
// it is compiled into stock Envoy builds and needs no Envoy-side change.
const mtlsAuthenticatedPrincipalName = "envoy.rbac.principals.mtls_authenticated"

// buildRBACPerRouteLegacy lowers an Authorization that matches on
// clientCert.subjectAltNames to the LEGACY RBAC `rules` API instead of the unified
// `matcher` API used by buildRBACPerRoute.
//
// Why a second code path exists at all
//
// Envoy's matcher inputs envoy.matching.inputs.uri_san and .dns_san join EVERY SAN of
// that type on the peer certificate into ONE comma-separated string. That encoding is
// not injective: a certificate holding the single URI SAN "A,B" produces exactly the
// same input value as a certificate holding the two URI SANs "A" and "B". Commas are
// legal in URI paths (RFC 3986), so a client can mint one SAN that impersonates a list
// containing an allowed value. No matcher over that input can distinguish the two
// cases, so SAN matching cannot be expressed safely on the matcher API at all.
//
// The legacy RBAC API can express it, via the envoy.rbac.principals.mtls_authenticated
// principal extension. That extension requires ssl->peerCertificateValidated() and then
// calls ssl->peerCertificateSanMatches(matcher), the same per-SAN helper the TLS
// validation context uses, which compares each SAN separately.
//
// Because a single RBAC filter instance honours either `rules` or `matcher` but not both
// ("When both rules and matcher are configured, rules will be ignored"), the choice is
// made once per Authorization: any rule matching on subjectAltNames sends the whole
// Authorization down this path, and everything else keeps the untouched matcher path.
//
// Semantics the legacy API cannot express are rejected earlier, at admission, by
// validateAuthorizationSANLowering in internal/gatewayapi/securitypolicy.go:
//   - a `cel` condition (legacy RBAC has no CEL principal),
//   - a `clientCert.subject` match (legacy RBAC has no correct Subject DN principal),
//   - rules whose actions differ from each other, or a defaultAction that is not the
//     opposite of the rule action: legacy `rules` carries ONE action plus an unordered
//     policy map, so first-match-wins over mixed Allow/Deny rules has no encoding.
//
// The checks are repeated here as a defence in depth: this function must never emit a
// config that silently drops a condition.
func buildRBACPerRouteLegacy(authorization *ir.Authorization) (*rbacv3.RBACPerRoute, error) {
	if len(authorization.Rules) == 0 {
		// Unreachable: this path is only selected when a rule matches on
		// subjectAltNames.
		return nil, errors.New("legacy RBAC lowering requires at least one authorization rule")
	}

	action, err := legacyRBACAction(authorization)
	if err != nil {
		return nil, err
	}

	policies := make(map[string]*rbacconfigv3.Policy, len(authorization.Rules))
	for _, rule := range authorization.Rules {
		if rule == nil {
			continue
		}
		if rule.CEL != nil {
			return nil, fmt.Errorf("authorization rule %q cannot combine cel with clientCert.subjectAltNames: "+
				"the legacy RBAC API required to match SANs safely has no CEL principal", rule.Name)
		}

		permission, err := buildLegacyPermission(rule.Operation)
		if err != nil {
			return nil, err
		}

		principal, err := buildLegacyPrincipal(&rule.Principal)
		if err != nil {
			return nil, fmt.Errorf("authorization rule %q: %w", rule.Name, err)
		}

		if _, exists := policies[rule.Name]; exists {
			// Legacy `policies` is a map keyed by rule name; two rules sharing a name
			// would silently collapse into one policy.
			return nil, fmt.Errorf("duplicate authorization rule name %q", rule.Name)
		}

		policies[rule.Name] = &rbacconfigv3.Policy{
			// Both lists are OR-combined by Envoy and must be non-empty, so exactly one
			// entry is emitted for each; AND-combination is expressed inside it.
			Permissions: []*rbacconfigv3.Permission{permission},
			Principals:  []*rbacconfigv3.Principal{principal},
		}
	}

	return &rbacv3.RBACPerRoute{
		Rbac: &rbacv3.RBAC{
			Rules: &rbacconfigv3.RBAC{
				Action:   action,
				Policies: policies,
			},
		},
	}, nil
}

// legacyRBACAction maps the IR rule actions and default action onto the single action
// carried by a legacy RBAC config.
//
// Legacy semantics are: with action ALLOW a request is allowed iff some policy matches
// and denied otherwise; with action DENY it is denied iff some policy matches and
// allowed otherwise. That is expressible only when every rule shares one action and the
// default action is its opposite. Anything else (mixed actions, or a default action
// equal to the rule action) depends on the ordered first-match-wins evaluation that only
// the matcher API provides.
func legacyRBACAction(authorization *ir.Authorization) (rbacconfigv3.RBAC_Action, error) {
	ruleAction := authorization.Rules[0].Action
	for _, rule := range authorization.Rules {
		if rule.Action != ruleAction {
			return rbacconfigv3.RBAC_ALLOW, errors.New(
				"authorization rules matching on clientCert.subjectAltNames must all use the same action")
		}
	}

	switch {
	case ruleAction == egv1a1.AuthorizationActionAllow && authorization.DefaultAction == egv1a1.AuthorizationActionDeny:
		return rbacconfigv3.RBAC_ALLOW, nil
	case ruleAction == egv1a1.AuthorizationActionDeny && authorization.DefaultAction == egv1a1.AuthorizationActionAllow:
		return rbacconfigv3.RBAC_DENY, nil
	default:
		return rbacconfigv3.RBAC_ALLOW, fmt.Errorf(
			"authorization matching on clientCert.subjectAltNames requires defaultAction to be the opposite of the rule action, got rule action %q and defaultAction %q",
			ruleAction, authorization.DefaultAction)
	}
}

// buildLegacyPermission lowers an Operation to a legacy RBAC Permission.
//
// Methods and path both lower to `:method`/`:path` pseudo-header matchers rather than
// Permission.url_path, to keep the matched value identical to the matcher API path
// (url_path matches the path with the query string stripped, the `:path` header does
// not).
func buildLegacyPermission(operation *egv1a1.Operation) (*rbacconfigv3.Permission, error) {
	if operation == nil {
		return anyPermission(), nil
	}

	var permissions []*rbacconfigv3.Permission

	if len(operation.Methods) > 0 {
		methodPermissions := make([]*rbacconfigv3.Permission, 0, len(operation.Methods))
		for _, method := range operation.Methods {
			methodPermissions = append(methodPermissions, headerPermission(exactHeaderMatcher(":method", string(method), true)))
		}
		permissions = append(permissions, orPermissions(methodPermissions))
	}

	if operation.Path != nil {
		stringMatcher, err := buildEnvoyPathStringMatcher(operation.Path)
		if err != nil {
			return nil, err
		}
		headerMatcher := &routev3.HeaderMatcher{
			Name: ":path",
			HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
				StringMatch: stringMatcher,
			},
			// HeaderMatcher inverts in place, so Operation.Path.Invert needs no
			// Permission.not_rule wrapper.
			InvertMatch: ptr.Deref(operation.Path.Invert, false),
		}
		permissions = append(permissions, headerPermission(headerMatcher))
	}

	if len(permissions) == 0 {
		return anyPermission(), nil
	}

	return andPermissions(permissions), nil
}

// buildLegacyPrincipal lowers an IR Principal to a single legacy RBAC Principal.
//
// Principal types AND-combine, mirroring the matcher API path: "if there are multiple
// principal types, all principals must match for the rule to match".
func buildLegacyPrincipal(principal *ir.Principal) (*rbacconfigv3.Principal, error) {
	if principal == nil {
		return anyPrincipal(), nil
	}

	var principals []*rbacconfigv3.Principal

	if len(principal.ClientCIDRs) > 0 {
		cidrPrincipals := make([]*rbacconfigv3.Principal, 0, len(principal.ClientCIDRs))
		for _, cidr := range principal.ClientCIDRs {
			cidrPrincipals = append(cidrPrincipals, &rbacconfigv3.Principal{
				// remote_ip, not direct_remote_ip: it reads the stream's downstream
				// remote address, which is what EG's ClientIPDetection (XFF, custom
				// header, PROXY protocol) rewrites, and so is the legacy counterpart of
				// the SourceIPInput the matcher path uses.
				Identifier: &rbacconfigv3.Principal_RemoteIp{
					RemoteIp: &configv3.CidrRange{
						AddressPrefix: cidr.AddressPrefix(),
						PrefixLen:     &wrapperspb.UInt32Value{Value: cidr.MaskLen},
					},
				},
			})
		}
		principals = append(principals, orPrincipals(cidrPrincipals))
	}

	for _, header := range principal.Headers {
		valuePrincipals := make([]*rbacconfigv3.Principal, 0, len(header.Values))
		for _, value := range header.Values {
			valuePrincipals = append(valuePrincipals, headerPrincipal(exactHeaderMatcher(header.Name, value, false)))
		}
		if len(valuePrincipals) == 0 {
			continue
		}
		// Values within one header OR-combine; separate headers AND-combine.
		principals = append(principals, orPrincipals(valuePrincipals))
	}

	if principal.JWT != nil {
		// Claims and scopes AND-combine.
		principals = append(principals, buildLegacyJWTPrincipals(*principal.JWT)...)
	}

	if len(principal.ClientIPGeoLocations) > 0 {
		geoPrincipal := buildLegacyGeoIPPrincipal(principal.ClientIPGeoLocations)
		if geoPrincipal != nil {
			principals = append(principals, geoPrincipal)
		}
	}

	if principal.ClientCert != nil {
		clientCertPrincipal, err := buildLegacyClientCertPrincipal(principal.ClientCert)
		if err != nil {
			return nil, err
		}
		principals = append(principals, clientCertPrincipal)
	}

	if len(principals) == 0 {
		return anyPrincipal(), nil
	}

	return andPrincipals(principals), nil
}

// buildLegacyClientCertPrincipal lowers clientCert.subjectAltNames to
// envoy.rbac.principals.mtls_authenticated principals.
//
// Every URI and DNS entry OR-combines into one group, preserving the matcher path's
// AND(subject, OR(uris..., dnsNames...)) shape minus the subject leg, which admission
// rejects in this mode.
func buildLegacyClientCertPrincipal(clientCert *egv1a1.ClientCertPrincipal) (*rbacconfigv3.Principal, error) {
	if clientCert.Subject != nil {
		return nil, errors.New("clientCert.subject cannot be combined with clientCert.subjectAltNames: " +
			"the legacy RBAC API required to match SANs safely has no correct Subject DN principal")
	}

	san := clientCert.SubjectAltNames
	if san == nil {
		// Unreachable: this path is only selected for principals carrying SANs.
		return nil, errors.New("clientCert.subjectAltNames is required in legacy RBAC lowering")
	}
	if len(san.EmailAddresses) > 0 || len(san.IPAddresses) > 0 || len(san.OtherNames) > 0 {
		return nil, errors.New("clientCert.subjectAltNames currently only supports uris and dnsNames; " +
			"emailAddresses/ipAddresses/otherNames are not yet supported")
	}
	if len(san.URIs) == 0 && len(san.DNSNames) == 0 {
		return nil, errors.New("clientCert.subjectAltNames must specify at least one entry in uris or dnsNames")
	}

	sanPrincipals := make([]*rbacconfigv3.Principal, 0, len(san.URIs)+len(san.DNSNames))
	for i := range san.URIs {
		p, err := buildMTLSAuthenticatedPrincipal(tlsv3.SubjectAltNameMatcher_URI, &san.URIs[i])
		if err != nil {
			return nil, err
		}
		sanPrincipals = append(sanPrincipals, p)
	}
	for i := range san.DNSNames {
		p, err := buildMTLSAuthenticatedPrincipal(tlsv3.SubjectAltNameMatcher_DNS, &san.DNSNames[i])
		if err != nil {
			return nil, err
		}
		sanPrincipals = append(sanPrincipals, p)
	}

	return orPrincipals(sanPrincipals), nil
}

// buildMTLSAuthenticatedPrincipal builds one mtls_authenticated principal matching a
// single SAN type/value pair.
//
// san_matcher is always set; the extension throws at config load if neither san_matcher
// nor any_validated_client_certificate is present. Because the extension takes a full
// SubjectAltNameMatcher (and therefore a full StringMatcher), Exact, Prefix, Suffix and
// RegularExpression all remain expressible, with no regex rewriting.
func buildMTLSAuthenticatedPrincipal(sanType tlsv3.SubjectAltNameMatcher_SanType, sm *egv1a1.StringMatch) (*rbacconfigv3.Principal, error) {
	stringMatcher, err := buildEnvoyStringMatcherFromEG(sm)
	if err != nil {
		return nil, err
	}

	cfg := &mtlsauthnv3.Config{
		SanMatcher: &tlsv3.SubjectAltNameMatcher{
			SanType: sanType,
			Matcher: stringMatcher,
		},
	}

	cfgAny, err := proto.ToAnyWithValidation(cfg)
	if err != nil {
		return nil, err
	}

	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_Custom{
			Custom: &configv3.TypedExtensionConfig{
				Name:        mtlsAuthenticatedPrincipalName,
				TypedConfig: cfgAny,
			},
		},
	}, nil
}

// buildLegacyJWTPrincipals mirrors buildJWTPredicate on the legacy API: scopes are read
// from both the "scope" and "scp" keys of the provider's jwt_authn metadata, claim
// values OR-combine, and claims and scopes AND-combine.
func buildLegacyJWTPrincipals(jwt egv1a1.JWTPrincipal) []*rbacconfigv3.Principal {
	principals := make([]*rbacconfigv3.Principal, 0, len(jwt.Scopes)+len(jwt.Claims))

	for _, scope := range jwt.Scopes {
		scopePrincipals := make([]*rbacconfigv3.Principal, 0, 2)
		for _, scopeKey := range []string{"scope", "scp"} {
			scopePrincipals = append(scopePrincipals, metadataPrincipal(
				[]string{jwt.Provider, scopeKey},
				// The scope has already been normalized to a string array by the JWT
				// Authn filter.
				listValueMatcher(string(scope)),
			))
		}
		principals = append(principals, orPrincipals(scopePrincipals))
	}

	for _, claim := range jwt.Claims {
		// A nested claim is represented as a dot-separated string, e.g. "user.email".
		path := append([]string{jwt.Provider}, strings.Split(claim.Name, ".")...)

		valuePrincipals := make([]*rbacconfigv3.Principal, 0, len(claim.Values))
		for _, value := range claim.Values {
			var valueMatcher *envoymatcherv3.ValueMatcher
			if claim.ValueType != nil && *claim.ValueType == egv1a1.JWTClaimValueTypeStringArray {
				valueMatcher = listValueMatcher(value)
			} else {
				valueMatcher = stringValueMatcher(value)
			}
			valuePrincipals = append(valuePrincipals, metadataPrincipal(path, valueMatcher))
		}
		if len(valuePrincipals) == 0 {
			continue
		}
		principals = append(principals, orPrincipals(valuePrincipals))
	}

	return principals
}

// buildLegacyGeoIPPrincipal mirrors buildGeoIPPredicate on the legacy API: fields within
// one location AND-combine, and locations OR-combine. The values are read from the
// internal headers the GeoIP filter writes, exactly as on the matcher path.
func buildLegacyGeoIPPrincipal(geoLocations []egv1a1.ClientIPGeoLocation) *rbacconfigv3.Principal {
	locationPrincipals := make([]*rbacconfigv3.Principal, 0, len(geoLocations))

	for _, geoLocation := range geoLocations {
		fieldPrincipals := make([]*rbacconfigv3.Principal, 0, 10)
		appendField := func(name, value string, ignoreCase bool) {
			fieldPrincipals = append(fieldPrincipals, headerPrincipal(exactHeaderMatcher(name, value, ignoreCase)))
		}

		if geoLocation.Country != nil {
			appendField(geoIPInternalCountryHeader, *geoLocation.Country, true)
		}
		if geoLocation.Region != nil {
			appendField(geoIPInternalRegionHeader, *geoLocation.Region, true)
		}
		if geoLocation.City != nil {
			appendField(geoIPInternalCityHeader, *geoLocation.City, true)
		}
		if geoLocation.ASN != nil {
			appendField(geoIPInternalASNHeader, strconv.FormatUint(uint64(*geoLocation.ASN), 10), false)
		}
		if geoLocation.ISP != nil {
			appendField(geoIPInternalISPHeader, *geoLocation.ISP, true)
		}
		if geoLocation.Anonymous != nil {
			if geoLocation.Anonymous.IsAnonymous != nil {
				appendField(geoIPInternalAnonHeader, strconv.FormatBool(*geoLocation.Anonymous.IsAnonymous), false)
			}
			if geoLocation.Anonymous.IsVPN != nil {
				appendField(geoIPInternalAnonVPNHeader, strconv.FormatBool(*geoLocation.Anonymous.IsVPN), false)
			}
			if geoLocation.Anonymous.IsHosting != nil {
				appendField(geoIPInternalAnonHostHeader, strconv.FormatBool(*geoLocation.Anonymous.IsHosting), false)
			}
			if geoLocation.Anonymous.IsTor != nil {
				appendField(geoIPInternalAnonTorHeader, strconv.FormatBool(*geoLocation.Anonymous.IsTor), false)
			}
			if geoLocation.Anonymous.IsProxy != nil {
				appendField(geoIPInternalAnonProxyHeader, strconv.FormatBool(*geoLocation.Anonymous.IsProxy), false)
			}
		}

		if len(fieldPrincipals) == 0 {
			continue
		}
		locationPrincipals = append(locationPrincipals, andPrincipals(fieldPrincipals))
	}

	if len(locationPrincipals) == 0 {
		return nil
	}

	return orPrincipals(locationPrincipals)
}

// buildEnvoyStringMatcherFromEG converts an EG StringMatch into an
// envoy.type.matcher.v3.StringMatcher, the flavour the legacy RBAC API and
// SubjectAltNameMatcher use. buildXdsStringMatcherFromEG is the same conversion for the
// cncf/xds flavour used by the unified matcher pipeline; the two proto packages are not
// interchangeable.
func buildEnvoyStringMatcherFromEG(sm *egv1a1.StringMatch) (*envoymatcherv3.StringMatcher, error) {
	matchType := egv1a1.StringMatchExact
	if sm.Type != nil {
		matchType = *sm.Type
	}
	switch matchType {
	case egv1a1.StringMatchExact:
		return &envoymatcherv3.StringMatcher{
			MatchPattern: &envoymatcherv3.StringMatcher_Exact{Exact: sm.Value},
		}, nil
	case egv1a1.StringMatchPrefix:
		return &envoymatcherv3.StringMatcher{
			MatchPattern: &envoymatcherv3.StringMatcher_Prefix{Prefix: sm.Value},
		}, nil
	case egv1a1.StringMatchSuffix:
		return &envoymatcherv3.StringMatcher{
			MatchPattern: &envoymatcherv3.StringMatcher_Suffix{Suffix: sm.Value},
		}, nil
	case egv1a1.StringMatchRegularExpression:
		return envoySafeRegexMatcher(sm.Value), nil
	}
	return nil, fmt.Errorf("unsupported StringMatch type: %q", matchType)
}

// buildEnvoyPathStringMatcher mirrors buildPathPredicate's path lowering, using the
// same regex helpers so the two code paths match identical requests.
func buildEnvoyPathStringMatcher(path *egv1a1.PathMatch) (*envoymatcherv3.StringMatcher, error) {
	switch ptr.Deref(path.Type, gwapiv1.PathMatchPathPrefix) {
	case gwapiv1.PathMatchPathPrefix:
		if path.Value == "/" {
			return &envoymatcherv3.StringMatcher{
				MatchPattern: &envoymatcherv3.StringMatcher_Prefix{Prefix: "/"},
			}, nil
		}
		return envoySafeRegexMatcher(regex.PathSeparatedPrefixRegex(path.Value)), nil
	case gwapiv1.PathMatchExact:
		return envoySafeRegexMatcher(regex.PathExactRegex(path.Value)), nil
	case gwapiv1.PathMatchRegularExpression:
		return envoySafeRegexMatcher(path.Value), nil
	default:
		return nil, fmt.Errorf("unsupported path match type: %q", ptr.Deref(path.Type, ""))
	}
}

func envoySafeRegexMatcher(pattern string) *envoymatcherv3.StringMatcher {
	return &envoymatcherv3.StringMatcher{
		MatchPattern: &envoymatcherv3.StringMatcher_SafeRegex{
			SafeRegex: &envoymatcherv3.RegexMatcher{
				Regex:      pattern,
				EngineType: &envoymatcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &envoymatcherv3.RegexMatcher_GoogleRE2{}},
			},
		},
	}
}

func exactHeaderMatcher(name, value string, ignoreCase bool) *routev3.HeaderMatcher {
	return &routev3.HeaderMatcher{
		Name: name,
		HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
			StringMatch: &envoymatcherv3.StringMatcher{
				MatchPattern: &envoymatcherv3.StringMatcher_Exact{Exact: value},
				IgnoreCase:   ignoreCase,
			},
		},
	}
}

func headerPermission(matcher *routev3.HeaderMatcher) *rbacconfigv3.Permission {
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_Header{Header: matcher},
	}
}

func headerPrincipal(matcher *routev3.HeaderMatcher) *rbacconfigv3.Principal {
	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_Header{Header: matcher},
	}
}

func metadataPrincipal(path []string, value *envoymatcherv3.ValueMatcher) *rbacconfigv3.Principal {
	segments := make([]*envoymatcherv3.MetadataMatcher_PathSegment, 0, len(path))
	for _, key := range path {
		segments = append(segments, &envoymatcherv3.MetadataMatcher_PathSegment{
			Segment: &envoymatcherv3.MetadataMatcher_PathSegment_Key{Key: key},
		})
	}

	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_Metadata{
			Metadata: &envoymatcherv3.MetadataMatcher{
				Filter: "envoy.filters.http.jwt_authn",
				Path:   segments,
				Value:  value,
			},
		},
	}
}

func stringValueMatcher(value string) *envoymatcherv3.ValueMatcher {
	return &envoymatcherv3.ValueMatcher{
		MatchPattern: &envoymatcherv3.ValueMatcher_StringMatch{
			StringMatch: &envoymatcherv3.StringMatcher{
				MatchPattern: &envoymatcherv3.StringMatcher_Exact{Exact: value},
			},
		},
	}
}

func listValueMatcher(value string) *envoymatcherv3.ValueMatcher {
	return &envoymatcherv3.ValueMatcher{
		MatchPattern: &envoymatcherv3.ValueMatcher_ListMatch{
			ListMatch: &envoymatcherv3.ListMatcher{
				MatchPattern: &envoymatcherv3.ListMatcher_OneOf{
					OneOf: stringValueMatcher(value),
				},
			},
		},
	}
}

func anyPermission() *rbacconfigv3.Permission {
	return &rbacconfigv3.Permission{Rule: &rbacconfigv3.Permission_Any{Any: true}}
}

func anyPrincipal() *rbacconfigv3.Principal {
	return &rbacconfigv3.Principal{Identifier: &rbacconfigv3.Principal_Any{Any: true}}
}

// andPermissions / orPermissions / andPrincipals / orPrincipals collapse a single-entry
// list to that entry, so the emitted config carries no redundant one-element set.
func andPermissions(permissions []*rbacconfigv3.Permission) *rbacconfigv3.Permission {
	if len(permissions) == 1 {
		return permissions[0]
	}
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_AndRules{
			AndRules: &rbacconfigv3.Permission_Set{Rules: permissions},
		},
	}
}

func orPermissions(permissions []*rbacconfigv3.Permission) *rbacconfigv3.Permission {
	if len(permissions) == 1 {
		return permissions[0]
	}
	return &rbacconfigv3.Permission{
		Rule: &rbacconfigv3.Permission_OrRules{
			OrRules: &rbacconfigv3.Permission_Set{Rules: permissions},
		},
	}
}

func andPrincipals(principals []*rbacconfigv3.Principal) *rbacconfigv3.Principal {
	if len(principals) == 1 {
		return principals[0]
	}
	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_AndIds{
			AndIds: &rbacconfigv3.Principal_Set{Ids: principals},
		},
	}
}

func orPrincipals(principals []*rbacconfigv3.Principal) *rbacconfigv3.Principal {
	if len(principals) == 1 {
		return principals[0]
	}
	return &rbacconfigv3.Principal{
		Identifier: &rbacconfigv3.Principal_OrIds{
			OrIds: &rbacconfigv3.Principal_Set{Ids: principals},
		},
	}
}

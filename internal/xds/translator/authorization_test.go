// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	matcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	sslinput "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/ssl/v3"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
)

// ---- buildXdsStringMatcherFromEG ----

func TestBuildXdsStringMatcherFromEG_NilTypeDefaultsToExact(t *testing.T) {
	sm := &egv1a1.StringMatch{Value: "example.com"} // Type is nil
	got, err := buildXdsStringMatcherFromEG(sm)
	require.NoError(t, err)
	exact, ok := got.MatchPattern.(*matcherv3.StringMatcher_Exact)
	require.True(t, ok, "expected Exact match pattern")
	require.Equal(t, "example.com", exact.Exact)
}

func TestBuildXdsStringMatcherFromEG_UnknownTypeReturnsError(t *testing.T) {
	sm := &egv1a1.StringMatch{
		Type:  ptr.To(egv1a1.StringMatchType("bogus")),
		Value: "x",
	}
	_, err := buildXdsStringMatcherFromEG(sm)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestBuildXdsStringMatcherFromEG_RegexHasGoogleRe2Engine(t *testing.T) {
	sm := &egv1a1.StringMatch{
		Type:  ptr.To(egv1a1.StringMatchRegularExpression),
		Value: "^spiffe://cluster\\.local/.*$",
	}
	got, err := buildXdsStringMatcherFromEG(sm)
	require.NoError(t, err)

	safeRegex, ok := got.MatchPattern.(*matcherv3.StringMatcher_SafeRegex)
	require.True(t, ok, "expected SafeRegex match pattern")
	require.Equal(t, "^spiffe://cluster\\.local/.*$", safeRegex.SafeRegex.Regex)
	// The GoogleRe2 engine must be set (this was the bug we fixed).
	googleRe2, ok := safeRegex.SafeRegex.EngineType.(*matcherv3.RegexMatcher_GoogleRe2)
	require.True(t, ok, "expected GoogleRe2 engine type")
	require.NotNil(t, googleRe2.GoogleRe2)
}

// ---- buildClientCertPredicate ----

// inputNameFromPredicate extracts the TypedExtensionConfig.Name from a
// SinglePredicate — it panics if the predicate is not a SinglePredicate.
func inputNameFromPredicate(p *matcherv3.Matcher_MatcherList_Predicate) string {
	sp := p.MatchType.(*matcherv3.Matcher_MatcherList_Predicate_SinglePredicate_)
	return sp.SinglePredicate.Input.Name
}

func TestBuildClientCertPredicate_SubjectOnly(t *testing.T) {
	cc := &egv1a1.ClientCertPrincipal{
		Subject: &egv1a1.StringMatch{Value: "CN=client.example.com"},
	}
	preds, err := buildClientCertPredicate(cc)
	require.NoError(t, err)
	require.Len(t, preds, 1)
	require.Equal(t, "client_cert_subject", inputNameFromPredicate(preds[0]))
}
// Compile-time check: sslinput is referenced so the import is not pruned.
var _ = (*sslinput.SubjectInput)(nil)

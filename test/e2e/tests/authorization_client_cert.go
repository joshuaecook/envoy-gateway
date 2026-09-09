// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build e2e

package tests

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	tlsutils "sigs.k8s.io/gateway-api/conformance/utils/tls"

	"github.com/envoyproxy/gateway/internal/gatewayapi"
	"github.com/envoyproxy/gateway/internal/gatewayapi/resource"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		AuthorizationClientCertTest,
		AuthorizationClientCertDNSSANTest,
		AuthorizationClientCertSubjectTest,
		AuthorizationClientCertSANForgeryTest,
	)
}

// AuthorizationClientCertTest verifies that SecurityPolicy authorization using
// the clientCert principal field correctly allows and denies requests based on
// the URI SAN of the client certificate presented during mTLS.
var AuthorizationClientCertTest = suite.ConformanceTest{
	ShortName:   "AuthorizationClientCertURISAN",
	Description: "SecurityPolicy authorization based on client certificate URI SAN",
	Manifests:   []string{"testdata/authorization-client-cert.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "authz-client-cert-allowed-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "authz-client-cert-gateway", Namespace: ns}

		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig,
			suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-uri-allow", Namespace: ns},
			suite.ControllerName, ancestorRef)

		// The server cert secret holds the CA in ca.crt; use it as the trust root to
		// verify the gateway's server certificate during the TLS handshake.
		_, _, serverCA, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-server-cert", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching server cert secret: %v", err)
		}

		allowedClientCert, allowedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-allowed", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching allowed client cert secret: %v", err)
		}

		deniedClientCert, deniedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-denied", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching denied client cert secret: %v", err)
		}

		t.Run("allow request with matching URI SAN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedClientCert, allowedClientKey,
				"authz-client-cert.example.com", expected)
		})

		t.Run("deny request with non-matching URI SAN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, deniedClientCert, deniedClientKey,
				"authz-client-cert.example.com", expected)
		})

		t.Run("reject request with no client certificate at TLS layer", func(t *testing.T) {
			// In TLS 1.3, Envoy completes the handshake even when no client cert is
			// presented (RFC 8446 allows empty Certificate), then rejects at the
			// application layer. Accept either form of rejection.
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(serverCA) {
				t.Fatal("failed to add server CA to cert pool")
			}
			// nolint: gosec
			tlsConfig := &tls.Config{
				ServerName: "authz-client-cert.example.com",
				RootCAs:    certPool,
				// No Certificates — no client cert presented.
			}
			conn, dialErr := tls.Dial("tcp", net.JoinHostPort(gwAddr, "443"), tlsConfig)
			if dialErr != nil {
				var alert tls.AlertError
				if !errors.As(dialErr, &alert) {
					t.Errorf("expected TLS alert, got non-TLS error: %v", dialErr)
					return
				}
				t.Logf("TLS alert %d received (no client cert presented)", alert)
				return
			}
			defer conn.Close()
			// Handshake succeeded; send HTTP request and verify denial.
			fmt.Fprintf(conn, "GET /allowed HTTP/1.0\r\nHost: authz-client-cert.example.com\r\n\r\n")
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			response := string(buf[:n])
			if strings.Contains(response, "HTTP/") && strings.Contains(response, " 200 ") {
				t.Errorf("expected denial without client certificate, got 200: %s", response)
			}
		})
	},
}

// AuthorizationClientCertDNSSANTest verifies that SecurityPolicy authorization using
// the clientCert principal field correctly allows and denies requests based on
// the DNS SAN of the client certificate presented during mTLS.
var AuthorizationClientCertDNSSANTest = suite.ConformanceTest{
	ShortName:   "AuthorizationClientCertDNSSAN",
	Description: "SecurityPolicy authorization based on client certificate DNS SAN",
	Manifests:   []string{"testdata/authorization-client-cert-dns.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "authz-client-cert-dns-allowed-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "authz-client-cert-dns-gateway", Namespace: ns}

		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig,
			suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-dns-allow", Namespace: ns},
			suite.ControllerName, ancestorRef)

		// The server cert secret holds the CA in ca.crt; use it as the trust root to
		// verify the gateway's server certificate during the TLS handshake.
		_, _, serverCA, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-dns-server-cert", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching server cert secret: %v", err)
		}

		allowedClientCert, allowedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-dns-allowed", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching allowed client cert secret: %v", err)
		}

		deniedClientCert, deniedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-dns-denied", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching denied client cert secret: %v", err)
		}

		t.Run("allow request with matching DNS SAN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-dns.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedClientCert, allowedClientKey,
				"authz-client-cert-dns.example.com", expected)
		})

		t.Run("deny request with non-matching DNS SAN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-dns.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, deniedClientCert, deniedClientKey,
				"authz-client-cert-dns.example.com", expected)
		})
	},
}

// AuthorizationClientCertSubjectTest verifies that SecurityPolicy authorization
// using the clientCert.subject field correctly allows and denies requests based
// on the Subject Distinguished Name of the client certificate presented during
// mTLS.
var AuthorizationClientCertSubjectTest = suite.ConformanceTest{
	ShortName:   "AuthorizationClientCertSubjectDN",
	Description: "SecurityPolicy authorization based on client certificate Subject Distinguished Name",
	Manifests:   []string{"testdata/authorization-client-cert-subject.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "authz-client-cert-subject-route", Namespace: ns}
		exactRouteNN := types.NamespacedName{Name: "authz-client-cert-subject-exact-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "authz-client-cert-subject-gateway", Namespace: ns}

		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig,
			suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN, exactRouteNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-subject-allow", Namespace: ns},
			suite.ControllerName, ancestorRef)
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-subject-exact-allow", Namespace: ns},
			suite.ControllerName, ancestorRef)

		// The server cert secret holds the CA in ca.crt; use it as the trust root to
		// verify the gateway's server certificate during the TLS handshake.
		_, _, serverCA, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-subject-server-cert", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching server cert secret: %v", err)
		}

		allowedClientCert, allowedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-subject-allowed", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching allowed client cert secret: %v", err)
		}

		deniedClientCert, deniedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-subject-denied", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching denied client cert secret: %v", err)
		}

		t.Run("allow request with matching Subject DN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-subject.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedClientCert, allowedClientKey,
				"authz-client-cert-subject.example.com", expected)
		})

		t.Run("deny request with non-matching Subject DN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-subject.example.com",
					Path: "/allowed",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, deniedClientCert, deniedClientKey,
				"authz-client-cert-subject.example.com", expected)
		})

		t.Run("allow request with exact Subject DN match", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-subject.example.com",
					Path: "/exact-allowed",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedClientCert, allowedClientKey,
				"authz-client-cert-subject.example.com", expected)
		})

		t.Run("deny request with non-matching Subject DN (exact match)", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-subject.example.com",
					Path: "/exact-allowed",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, deniedClientCert, deniedClientKey,
				"authz-client-cert-subject.example.com", expected)
		})
	},
}

// AuthorizationClientCertCombined verifies that SecurityPolicy authorization using
// the clientCert principal field with both subject AND subjectAltNames.uris correctly
// allows and denies requests based on both constraints being satisfied (AND semantics).
var AuthorizationClientCertCombined = suite.ConformanceTest{
	ShortName:   "AuthorizationClientCertCombined",
	Description: "SecurityPolicy authorization based on client certificate subject AND URI SAN",
	Manifests:   []string{"testdata/authorization-client-cert-combined.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "authz-client-cert-combined-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "authz-client-cert-combined-gateway", Namespace: ns}

		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig,
			suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-combined-policy", Namespace: ns},
			suite.ControllerName, ancestorRef)

		// The server cert secret holds the CA in ca.crt; use it as the trust root to
		// verify the gateway's server certificate during the TLS handshake.
		_, _, serverCA, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-combined-server-cert", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching server cert secret: %v", err)
		}

		// Cert that matches both subject AND URI (should be allowed)
		allowedClientCert, allowedClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-combined-allowed", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching allowed client cert secret: %v", err)
		}

		// Cert that matches subject but wrong URI (should be denied)
		wrongURIClientCert, wrongURIClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-combined-wrong-uri", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching wrong-uri client cert secret: %v", err)
		}

		// Cert that matches URI but wrong subject (should be denied)
		wrongSubjectClientCert, wrongSubjectClientKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-combined-wrong-subject", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching wrong-subject client cert secret: %v", err)
		}

		t.Run("allow-both-matching", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-combined.example.com",
					Path: "/",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedClientCert, allowedClientKey,
				"authz-client-cert-combined.example.com", expected)
		})

		t.Run("deny-wrong-uri", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-combined.example.com",
					Path: "/",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, wrongURIClientCert, wrongURIClientKey,
				"authz-client-cert-combined.example.com", expected)
		})

		t.Run("deny-wrong-subject", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host: "authz-client-cert-combined.example.com",
					Path: "/",
				},
				Response: http.Response{
					StatusCodes: []int{403},
				},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, wrongSubjectClientCert, wrongSubjectClientKey,
				"authz-client-cert-combined.example.com", expected)
		})
	},
}

// AuthorizationClientCertSANForgeryTest is the regression test for the SAN-forgery bypass.
//
// Envoy's uri_san/dns_san matcher inputs join every SAN of a type into ONE comma-separated
// string, and that encoding is not injective: a certificate holding the single SAN
// "decoy,allowed" produces the same input value as one holding the two SANs
// {"decoy", "allowed"}. Commas are legal inside a URI (RFC 3986), so a peer can hold such
// a SAN legitimately. Any matcher built over the joined string therefore authorizes the
// forger — verified 200 against the previous comma-boundary regex implementation.
//
// Lowering SAN matching to the legacy RBAC envoy.rbac.principals.mtls_authenticated
// principal evaluates SANs individually, so the forger must be denied.
var AuthorizationClientCertSANForgeryTest = suite.ConformanceTest{
	ShortName:   "AuthorizationClientCertSANForgery",
	Description: "A single SAN containing a comma must not forge a SAN boundary",
	Manifests:   []string{"testdata/authorization-client-cert-forgery.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		host := "authz-client-cert-forgery.example.com"
		routeNN := types.NamespacedName{Name: "authz-client-cert-forgery-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "authz-client-cert-forgery-gateway", Namespace: ns}

		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig,
			suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN)

		ancestorRef := gwapiv1.ParentReference{
			Group:     gatewayapi.GroupPtr(gwapiv1.GroupName),
			Kind:      gatewayapi.KindPtr(resource.KindGateway),
			Namespace: gatewayapi.NamespacePtr(gwNN.Namespace),
			Name:      gwapiv1.ObjectName(gwNN.Name),
		}
		SecurityPolicyMustBeAccepted(t, suite.Client,
			types.NamespacedName{Name: "authz-client-cert-forgery-allow", Namespace: ns},
			suite.ControllerName, ancestorRef)

		_, _, serverCA, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-forgery-server-cert", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching server cert secret: %v", err)
		}

		allowedCert, allowedKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-forgery-allowed", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching allowed client cert secret: %v", err)
		}

		forgerCert, forgerKey, _, err := GetTLSSecret(suite.Client,
			types.NamespacedName{Name: "authz-client-cert-forgery-forger", Namespace: ns})
		if err != nil {
			t.Fatalf("unexpected error fetching forger client cert secret: %v", err)
		}

		// Positive control. Without this, a blanket denial would look like a pass.
		t.Run("allow the certificate that genuinely holds the permitted SAN", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request:   http.Request{Host: host, Path: "/allowed"},
				Response:  http.Response{StatusCodes: []int{200}},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, allowedCert, allowedKey, host, expected)
		})

		t.Run("deny the certificate whose single SAN embeds the permitted value after a comma", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request:   http.Request{Host: host, Path: "/allowed"},
				Response:  http.Response{StatusCodes: []int{403}},
				Namespace: ns,
			}
			tlsutils.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper,
				suite.TimeoutConfig, gwAddr, serverCA, forgerCert, forgerKey, host, expected)
		})
	},
}

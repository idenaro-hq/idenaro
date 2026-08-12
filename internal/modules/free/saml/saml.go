package saml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/modules/free/saml/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "saml"

// MetadataPaths is the ordered list of paths probed to locate SAML metadata.
// Exported so pro/saml can reuse the same probe sequence.
var MetadataPaths = []string{
	"/saml/metadata",
	"/saml2/metadata",
	"/metadata",
	"/saml/metadata.xml",
	"/auth/saml/metadata",
	"/sso/saml/metadata",
	"/idp/metadata",
	"/realms/master/protocol/saml/descriptor",
	"/adfs/FederationMetadata/2007-06/FederationMetadata.xml",
}

// EntityDescriptor is the root SAML metadata element.
// Exported so pro/saml can reuse the parsed type.
type EntityDescriptor struct {
	XMLName          xml.Name          `xml:"EntityDescriptor"`
	EntityID         string            `xml:"entityID,attr"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor"`
}

// IDPSSODescriptor contains IdP-specific metadata.
type IDPSSODescriptor struct {
	WantAuthnRequestsSigned string                `xml:"WantAuthnRequestsSigned,attr"`
	SingleSignOnServices    []SingleSignOnService `xml:"SingleSignOnService"`
	SingleLogoutServices    []SingleLogoutService `xml:"SingleLogoutService"`
	KeyDescriptors          []KeyDescriptor       `xml:"KeyDescriptor"`
}

// SPSSODescriptor contains SP-specific metadata.
type SPSSODescriptor struct {
	WantAssertionsSigned      string          `xml:"WantAssertionsSigned,attr"`
	AuthnRequestsSigned       string          `xml:"AuthnRequestsSigned,attr"`
	AssertionConsumerServices []ACS           `xml:"AssertionConsumerService"`
	KeyDescriptors            []KeyDescriptor `xml:"KeyDescriptor"`
}

// SingleSignOnService describes a SAML SSO binding and its location.
type SingleSignOnService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// SingleLogoutService describes a SAML SLO binding.
type SingleLogoutService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// ACS is an AssertionConsumerService endpoint.
type ACS struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    string `xml:"index,attr"`
}

// KeyDescriptor holds a public key used for signing or encryption.
type KeyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"KeyInfo"`
}

// KeyInfo wraps the X.509 certificate data.
type KeyInfo struct {
	X509Data X509Data `xml:"X509Data"`
}

// X509Data holds the base64-encoded DER certificate.
type X509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	var findings []finding.Finding

	realm := target.RealmOrDefault()
	for _, path := range MetadataPaths {
		path = strings.ReplaceAll(path, "/realms/master/", "/realms/"+realm+"/")
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}

		responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		if !strings.Contains(string(responseBody), "EntityDescriptor") {
			continue
		}

		f := finding.NewFinding(moduleName, target.Host,
			"SAML Metadata publicly accessible",
			fmt.Sprintf("SAML metadata is accessible at %s. This exposes IdP/SP configuration, "+
				"endpoints, and signing certificates.", pageURL),
			finding.Info,
		)
		f.ID = "saml-metadata"
		f.Evidence = []string{pageURL, fmt.Sprintf("HTTP %d", resp.StatusCode)}
		f.Confidence = "HIGH"
		f.Recommendation = "Expected for federated SSO. Verify certificates are current and endpoints are intentional."
		f.Tags = []string{"saml", "iam"}
		findings = append(findings, f)

		var meta EntityDescriptor
		if err := xml.Unmarshal(responseBody, &meta); err == nil && meta.IDPSSODescriptor != nil {
			ssoServices := make([]checks.SSOService, len(meta.IDPSSODescriptor.SingleSignOnServices))
			for i, svc := range meta.IDPSSODescriptor.SingleSignOnServices {
				ssoServices[i] = checks.SSOService{Binding: svc.Binding, Location: svc.Location}
			}
			findings = append(findings, checks.Bindings(target.Host, ssoServices)...)
		}

		break
	}

	return findings, nil
}

// FetchMetadata probes all known metadata paths and returns the raw XML and the
// URL that succeeded. Exported so pro/saml can reuse the same probe sequence.
func FetchMetadata(ctx context.Context, client *http.Client, target modules.Target) ([]byte, string) {
	realm := target.RealmOrDefault()
	for _, path := range MetadataPaths {
		path = strings.ReplaceAll(path, "/realms/master/", "/realms/"+realm+"/")
		pageURL := target.BaseURL() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", httpclient.DefaultUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		if strings.Contains(string(body), "EntityDescriptor") {
			return body, pageURL
		}
	}
	return nil, ""
}

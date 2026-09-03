package samlpro

import (
	"context"
	"encoding/xml"
	"net/http"

	"idenaro/internal/finding"
	"idenaro/internal/modules"
	freesaml "idenaro/internal/modules/free/saml"
	samlchecks "idenaro/internal/modules/pro/saml/checks"
	"idenaro/pkg/httpclient"
)

const moduleName = "saml-pro"

type Scanner struct {
	httpClient *http.Client
}

func New(opts httpclient.Options) modules.Module {
	return &Scanner{httpClient: httpclient.New(opts)}
}

func (s *Scanner) Name() string { return moduleName }

func (s *Scanner) Run(ctx context.Context, target modules.Target) ([]finding.Finding, error) {
	xmlBytes, _ := freesaml.FetchMetadata(ctx, s.httpClient, target)
	if xmlBytes == nil {
		return nil, nil
	}

	var meta freesaml.EntityDescriptor
	if err := xml.Unmarshal(xmlBytes, &meta); err != nil {
		return nil, nil
	}

	var findings []finding.Finding
	findings = append(findings, analyzeIDP(meta, target.Host)...)
	findings = append(findings, analyzeSP(meta, target.Host)...)
	return findings, nil
}

func analyzeIDP(meta freesaml.EntityDescriptor, host string) []finding.Finding {
	if meta.IDPSSODescriptor == nil {
		return nil
	}
	idp := meta.IDPSSODescriptor
	keyDescs := toChecksKeyDescriptors(idp.KeyDescriptors)
	return samlchecks.IDP(host, idp.WantAuthnRequestsSigned, keyDescs)
}

func analyzeSP(meta freesaml.EntityDescriptor, host string) []finding.Finding {
	if meta.SPSSODescriptor == nil {
		return nil
	}
	sp := meta.SPSSODescriptor

	acsEndpoints := make([]samlchecks.ACSEndpoint, len(sp.AssertionConsumerServices))
	for i, acs := range sp.AssertionConsumerServices {
		acsEndpoints[i] = samlchecks.ACSEndpoint{Location: acs.Location}
	}

	keyDescs := toChecksKeyDescriptors(sp.KeyDescriptors)
	return samlchecks.SP(host, sp.WantAssertionsSigned, sp.AuthnRequestsSigned, acsEndpoints, keyDescs)
}

func toChecksKeyDescriptors(src []freesaml.KeyDescriptor) []samlchecks.KeyDescriptor {
	out := make([]samlchecks.KeyDescriptor, len(src))
	for i, kd := range src {
		out[i] = samlchecks.KeyDescriptor{
			Use:     kd.Use,
			CertB64: kd.KeyInfo.X509Data.X509Certificate,
		}
	}
	return out
}

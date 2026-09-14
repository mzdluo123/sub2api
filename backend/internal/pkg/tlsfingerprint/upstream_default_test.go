package tlsfingerprint

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestDefaultUpstreamClientHelloProfile_MatchesCapturedJA3Shape(t *testing.T) {
	profile := DefaultUpstreamClientHelloProfile()
	spec := buildClientHelloSpecFromProfile(profile)

	if len(spec.CipherSuites) != 18 {
		t.Fatalf("cipher suites: got %d want 18", len(spec.CipherSuites))
	}
	wantCiphers := []uint16{
		0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027,
		0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
	}
	for i, want := range wantCiphers {
		if spec.CipherSuites[i] != want {
			t.Fatalf("cipher[%d]: got 0x%04x want 0x%04x", i, spec.CipherSuites[i], want)
		}
	}

	if spec.TLSVersMax != utls.VersionTLS12 || spec.TLSVersMin != utls.VersionTLS12 {
		t.Fatalf("TLS version bounds: min=0x%04x max=0x%04x want TLS1.2 only", spec.TLSVersMin, spec.TLSVersMax)
	}

	// Extension type order must match JA3: 0-10-11-13-35-23-65281
	wantExtTypes := []uint16{0, 10, 11, 13, 35, 23, 0xff01}
	if len(spec.Extensions) != len(wantExtTypes) {
		t.Fatalf("extensions: got %d want %d", len(spec.Extensions), len(wantExtTypes))
	}
	for i, want := range wantExtTypes {
		got := extensionTypeID(spec.Extensions[i])
		if got != want {
			t.Fatalf("extension[%d]: got %d want %d", i, got, want)
		}
	}
}

func TestWithHTTP2ALPN_AppendsALPNExtension(t *testing.T) {
	profile := WithHTTP2ALPN(DefaultUpstreamClientHelloProfile())
	spec := buildClientHelloSpecFromProfile(profile)

	foundALPN := false
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			foundALPN = true
			break
		}
	}
	if !foundALPN {
		t.Fatal("expected ALPN extension for HTTP/2 profile")
	}
	if len(profile.ALPNProtocols) != 2 || profile.ALPNProtocols[0] != "h2" {
		t.Fatalf("ALPN protocols: got %v", profile.ALPNProtocols)
	}
}

func extensionTypeID(ext utls.TLSExtension) uint16 {
	switch e := ext.(type) {
	case *utls.SNIExtension:
		return 0
	case *utls.SupportedCurvesExtension:
		return 10
	case *utls.SupportedPointsExtension:
		return 11
	case *utls.SignatureAlgorithmsExtension:
		return 13
	case *utls.ALPNExtension:
		return 16
	case *utls.ExtendedMasterSecretExtension:
		return 23
	case *utls.SessionTicketExtension:
		return 35
	case *utls.RenegotiationInfoExtension:
		return 0xff01
	default:
		if g, ok := e.(*utls.GenericExtension); ok {
			return g.Id
		}
		return 0xffff
	}
}

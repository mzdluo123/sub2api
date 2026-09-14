package tlsfingerprint

// DefaultUpstreamClientHelloProfile returns the explicit default Client Hello used by
// upstream AI API HTTP clients (ChatGPT / Codex / OpenAI gateway path via http.Transport).
//
// Captured against chatgpt.com (local proxy path), Wireshark Client Hello:
//
//	Record/Handshake version: TLS 1.2 (0x0303)
//	Cipher Suites (18): see CipherSuites below (JA3 order)
//	Extensions (JA3 order): server_name(0), supported_groups(10), ec_point_formats(11),
//	  signature_algorithms(13), session_ticket(35), extended_master_secret(23),
//	  renegotiation_info(0xff01)
//	Supported Groups: x25519 (0x001d), secp256r1 (0x0017), secp384r1 (0x0018)
//	EC point formats: uncompressed (0)
//
// JA3:      6a5d235ee78c6aede6a61448b4e9ff1e
// JA3 full: 771,49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47,0-10-11-13-35-23-65281,29-23-24,0
// JA4:      t12d180700_4b22cbed5bed_2dae41c691ec
//
// No ALPN / supported_versions / key_share — TLS 1.2 only Client Hello.
// Call WithHTTP2ALPN when the transport must negotiate HTTP/2.
func DefaultUpstreamClientHelloProfile() *Profile {
	return &Profile{
		Name: "upstream_default_tls12_chatgpt",
		CipherSuites: []uint16{
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (49196)
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (49195)
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   (49200)
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   (49199)
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (49188)
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (49187)
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   (49192)
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   (49191)
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    (49162)
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    (49161)
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      (49172)
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      (49171)
			0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384         (157)
			0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256         (156)
			0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256         (61)
			0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256         (60)
			0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA            (53)
			0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA            (47)
		},
		Curves: []uint16{
			0x001d, // x25519
			0x0017, // secp256r1
			0x0018, // secp384r1
		},
		PointFormats: []uint16{
			0, // uncompressed
		},
		SignatureAlgorithms: []uint16{
			0x0804, // rsa_pss_rsae_sha256
			0x0805, // rsa_pss_rsae_sha384
			0x0806, // rsa_pss_rsae_sha512
			0x0401, // rsa_pkcs1_sha256
			0x0501, // rsa_pkcs1_sha384
			0x0201, // rsa_pkcs1_sha1
			0x0403, // ecdsa_secp256r1_sha256
			0x0503, // ecdsa_secp384r1_sha384
			0x0203, // ecdsa_sha1
			0x0202, // SHA1 DSA
			0x0601, // rsa_pkcs1_sha512
			0x0603, // ecdsa_secp521r1_sha512
		},
		// Empty ALPNProtocols + no extension 16 ⇒ do not send ALPN (matches capture).
		ALPNProtocols: nil,
		// Drives ClientHello legacy version / TLSVersMax even when extension 43 is omitted.
		SupportedVersions: []uint16{
			0x0303, // TLS 1.2
		},
		Extensions: []uint16{
			0,      // server_name
			10,     // supported_groups
			11,     // ec_point_formats
			13,     // signature_algorithms
			35,     // session_ticket
			23,     // extended_master_secret
			0xff01, // renegotiation_info
		},
		EnableGREASE: false,
	}
}

// WithHTTP2ALPN returns a copy of profile with ALPN h2/http1.1 appended.
// This is required for ForceAttemptHTTP2 / HTTP/2 keepalive paths, but changes JA3
// relative to DefaultUpstreamClientHelloProfile (capture has no ALPN).
func WithHTTP2ALPN(profile *Profile) *Profile {
	if profile == nil {
		profile = DefaultUpstreamClientHelloProfile()
	}
	out := *profile
	out.Name = profile.Name + "+h2_alpn"
	out.ALPNProtocols = []string{"h2", "http/1.1"}

	exts := make([]uint16, 0, len(profile.Extensions)+1)
	alpnSeen := false
	for _, id := range profile.Extensions {
		if id == 16 {
			alpnSeen = true
		}
		exts = append(exts, id)
	}
	if !alpnSeen {
		exts = append(exts, 16) // alpn
	}
	out.Extensions = exts
	return &out
}

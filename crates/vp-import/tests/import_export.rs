// Test assertions intentionally panic on unexpected fixture/results.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Source-authored tests. NOT RUN: repository execution permission is pending.
use base64::{engine::general_purpose::STANDARD, Engine};
use vp_product_domain::*;
use vp_product_import::*;

fn candidate(input: &str) -> ImportCandidate {
    let mut batch = parse(input.as_bytes(), ImportFormat::NodeUri).unwrap();
    assert_eq!(batch.entries.len(), 1);
    let entry = batch.entries.remove(0);
    assert!(entry.diagnostics.is_empty(), "{:?}", entry.diagnostics);
    entry.candidate.unwrap()
}
fn rejection(input: &str) -> ImportIssue {
    let mut batch = parse(input.as_bytes(), ImportFormat::NodeUri).unwrap();
    assert!(batch.entries[0].candidate.is_none());
    batch.entries.remove(0).diagnostics.remove(0)
}
// Test-only stand-in for deliberately persisted synthetic credentials. The
// production importer never fabricates refs or implements a vault allocator.
fn bind(c: ImportCandidate) -> (NodeProfile, SecretBundle) {
    let s = c.secrets();
    let secrets = SecretBundle {
        credential: Credential {
            kind: s.credential.kind,
            primary: SecretBytes::new(s.credential.primary.expose().to_vec()),
            secondary: s
                .credential
                .secondary
                .as_ref()
                .map(|v| SecretBytes::new(v.expose().to_vec())),
        },
        obfuscation: s
            .obfuscation
            .as_ref()
            .map(|v| SecretBytes::new(v.expose().to_vec())),
    };
    let allocated = AllocatedSecrets {
        credential_ref: SecretRef::new("test-fixture-credential").unwrap(),
        obfuscation_ref: if secrets.obfuscation.is_some() {
            Some(SecretRef::new("test-fixture-obfs").unwrap())
        } else {
            None
        },
    };
    (
        c.materialize(NodeId::new("test-node").unwrap(), None, allocated)
            .unwrap(),
        secrets,
    )
}
fn roundtrip(input: &str) {
    let c = candidate(input);
    let preview = c.preview().clone();
    let (node, secrets) = bind(c);
    let output = export_uri(&node, &secrets).unwrap();
    let reparsed = candidate(output.expose());
    assert_eq!(reparsed.preview(), &preview);
    assert_eq!(reparsed.secrets().credential.kind, secrets.credential.kind);
    assert_eq!(
        reparsed.secrets().credential.primary.expose(),
        secrets.credential.primary.expose()
    );
    assert_eq!(
        reparsed
            .secrets()
            .credential
            .secondary
            .as_ref()
            .map(SecretBytes::expose),
        secrets
            .credential
            .secondary
            .as_ref()
            .map(SecretBytes::expose)
    );
    assert_eq!(
        reparsed
            .secrets()
            .obfuscation
            .as_ref()
            .map(SecretBytes::expose),
        secrets.obfuscation.as_ref().map(SecretBytes::expose)
    );
}
#[test]
fn supported_scheme_fixtures_roundtrip() {
    for line in include_str!("../../../tests/fixtures/import/uris.txt").lines() {
        roundtrip(line.trim());
    }
}
#[test]
fn all_seven_shadowsocks_ciphers_roundtrip() {
    for method in [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        let secret = if method == "2022-blake3-aes-128-gcm" {
            "AAAAAAAAAAAAAAAAAAAAAA%3D%3D"
        } else if method.starts_with("2022") {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"
        } else {
            "fixture%3A%40%2B%25%23%3F%2F%E5%AF%86%E7%A0%81"
        };
        roundtrip(&format!(
            "ss://{method}:{secret}@[2001:db8::1]:8388#Name%20%2B%20%E7%BD%91"
        ));
    }
}
#[test]
fn ss_base64_userinfo_is_supported() {
    let auth = STANDARD.encode(b"aes-128-gcm:fixture-secret");
    roundtrip(&format!("ss://{auth}@proxy.example.invalid:8388"));
}
#[test]
fn ss2022_requires_plain_userinfo_and_correct_key_length() {
    let auth = STANDARD.encode(b"2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==");
    assert_eq!(
        rejection(&format!("ss://{auth}@proxy.example.invalid:8388")).kind,
        IssueKind::InvalidValue
    );
    assert_eq!(
        rejection("ss://2022-blake3-aes-128-gcm:YWJj@proxy.example.invalid:8388").kind,
        IssueKind::InvalidValue
    );
}
#[test]
fn duplicate_decoded_query_keys_fail() {
    assert_eq!(
        rejection("hy2://fixture@proxy.example.invalid?sni=a.invalid&%73ni=b.invalid").kind,
        IssueKind::DuplicateField
    );
}
#[test]
fn plus_is_literal_not_form_urlencoded_space() {
    let c = candidate("anytls://fixture+secret@proxy.example.invalid#A+B");
    assert_eq!(c.secrets().credential.primary.expose(), b"fixture+secret");
    assert_eq!(c.preview().name, "A+B");
}
#[test]
fn query_syntax_and_invalid_percent_encodings_fail() {
    for input in [
        "anytls://fixture%ZZ@proxy.example.invalid",
        "anytls://fixture%@proxy.example.invalid",
        "anytls://fixture%00@proxy.example.invalid",
        "anytls://fixture%FF@proxy.example.invalid",
        "anytls://fixture@proxy.example.invalid?sni",
        "anytls://fixture@proxy.example.invalid?",
    ] {
        assert!(rejection(input).error.field_path.is_some());
    }
}
#[test]
fn rejects_insecure_and_certificate_pin_downgrades() {
    assert_eq!(
        rejection("hy2://fixture@proxy.example.invalid?insecure=1").kind,
        IssueKind::InsecureTrust
    );
    assert_eq!(
        rejection("anytls://fixture@proxy.example.invalid?insecure=true").kind,
        IssueKind::InsecureTrust
    );
    assert_eq!(
        rejection("hy2://fixture@proxy.example.invalid?pinSHA256=abcd").kind,
        IssueKind::UnsupportedFeature
    );
    roundtrip("anytls://fixture@proxy.example.invalid?insecure=0");
}
#[test]
fn unknown_fields_are_never_dropped() {
    let e = rejection("anytls://fixture@proxy.example.invalid?unknown-secret-name=secret-value");
    assert_eq!(e.kind, IssueKind::UnknownField);
    let diagnostic = serde_json::to_string(&e).unwrap();
    assert!(!diagnostic.contains("unknown-secret-name"));
    assert!(!diagnostic.contains("secret-value"));
}
#[test]
fn endpoint_ipv6_and_port_bounds() {
    for input in [
        "anytls://fixture@[2001:db8::1]:0",
        "anytls://fixture@[2001:db8::1]:65536",
        "anytls://fixture@2001:db8::1:443",
        "anytls://fixture@[fe80::1%25eth0]:443",
        "anytls://fixture@bad_host:443",
        "anytls://fixture@host.invalid:+443",
    ] {
        rejection(input);
    }
    roundtrip("anytls://fixture@[2001:db8::1]:65535");
}
#[test]
fn hy2_port_hopping_and_obfs_extensions_are_explicitly_unsupported() {
    assert_eq!(
        rejection("hy2://fixture@host.invalid:443,8443").kind,
        IssueKind::UnsupportedFeature
    );
    assert_eq!(
        rejection("hy2://fixture@host.invalid?obfs=gecko&obfs-password=fixture").kind,
        IssueKind::UnsupportedFeature
    );
}
#[test]
fn reality_requires_fingerprint_and_valid_public_key() {
    let base = "vless://00000000-0000-4000-8000-000000000001@host.invalid:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(rejection(base).kind, IssueKind::InvalidValue);
    roundtrip(&format!("{base}&fp=chrome"));
}
#[test]
fn xray_tls_default_clienthello_is_preserved() {
    let c = candidate("vmess://00000000-0000-4000-8000-000000000001@host.invalid:443?security=tls");
    assert!(
        matches!(&c.preview().security, ClientSecurity::Tls { client_hello_fingerprint: Some(fp), .. } if fp == "chrome")
    );
}
#[test]
fn http_and_quic_names_never_map_to_tcp_or_h2() {
    for transport in ["http", "h2", "quic", "grpc", "kcp", "xhttp"] {
        assert_eq!(
            rejection(&format!(
                "vmess://00000000-0000-4000-8000-000000000001@host.invalid:443?type={transport}"
            ))
            .kind,
            IssueKind::UnsupportedFeature
        );
    }
}
#[test]
fn plaintext_is_not_mislabeled_as_tls() {
    let c = candidate("socks5://host.invalid:1080");
    assert_eq!(c.preview().security, ClientSecurity::None {});
    assert_eq!(c.secrets().credential.kind, CredentialKind::None);
    roundtrip("socks5://host.invalid:1080");
}
#[test]
fn multiline_retains_indexed_rejections() {
    let batch = parse(
        b"anytls://fixture@host.invalid\n\nnot-a-uri\nhy2://fixture@host.invalid",
        ImportFormat::UriList,
    )
    .unwrap();
    assert_eq!(
        batch.entries.iter().map(|e| e.index).collect::<Vec<_>>(),
        vec![0, 2, 3]
    );
    assert!(batch.entries[0].candidate.is_some());
    assert!(batch.entries[1].candidate.is_none());
    assert!(batch.has_unimported_fields);
}
#[test]
fn explicit_base64_subscription_does_not_recursively_decode() {
    let source = "anytls://fixture@host.invalid\nhy2://fixture@host.invalid";
    let encoded = STANDARD.encode(source);
    let batch = parse(encoded.as_bytes(), ImportFormat::Base64UriList).unwrap();
    assert_eq!(batch.format, ImportFormat::Base64UriList);
    assert_eq!(batch.entries.len(), 2);
    assert!(batch.entries.iter().all(|e| e.candidate.is_some()));
    assert_eq!(
        parse(encoded.as_bytes(), ImportFormat::Auto)
            .unwrap_err()
            .kind,
        IssueKind::UnsupportedFormat
    );
    let double = STANDARD.encode(encoded);
    assert!(parse(double.as_bytes(), ImportFormat::Base64UriList)
        .unwrap()
        .entries[0]
        .candidate
        .is_none());
}
#[test]
fn input_entry_component_query_and_utf8_limits() {
    assert_eq!(
        parse(&vec![b'a'; MAX_INPUT_BYTES + 1], ImportFormat::Auto)
            .unwrap_err()
            .kind,
        IssueKind::InputLimit
    );
    assert_eq!(
        parse(&[0xff], ImportFormat::Auto).unwrap_err().kind,
        IssueKind::InvalidUtf8
    );
    let flood = "anytls://fixture@host.invalid\n".repeat(MAX_ENTRIES + 1);
    assert_eq!(
        parse(flood.as_bytes(), ImportFormat::UriList)
            .unwrap_err()
            .kind,
        IssueKind::InputLimit
    );
    let large = format!(
        "anytls://{}@host.invalid",
        "a".repeat(MAX_COMPONENT_BYTES + 1)
    );
    assert_eq!(rejection(&large).kind, IssueKind::InputLimit);
    let query = (0..MAX_QUERY_FIELDS + 1)
        .map(|i| format!("a{i}=b"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(
        rejection(&format!("anytls://fixture@host.invalid?{query}")).kind,
        IssueKind::InputLimit
    );
}
#[test]
fn structured_extraction_is_not_full_config_support() {
    let b = parse(
        include_bytes!("../../../tests/fixtures/import/clash-nodes.json"),
        ImportFormat::Auto,
    )
    .unwrap();
    assert_eq!(b.format, ImportFormat::ClashNodes);
    assert_eq!(b.entries.len(), 2);
    assert!(b.entries.iter().all(|e| e.candidate.is_some()));
    assert!(b.has_unimported_fields);
    assert_eq!(b.diagnostics[0].kind, IssueKind::UnimportedTopLevelFields);
    let b = parse(
        include_bytes!("../../../tests/fixtures/import/sing-box-nodes.json"),
        ImportFormat::Auto,
    )
    .unwrap();
    assert_eq!(b.format, ImportFormat::SingBoxOutbounds);
    assert_eq!(b.entries.len(), 4);
    assert!(b.entries.iter().all(|e| e.candidate.is_some()));
    assert!(!b.has_unimported_fields);
}
#[test]
fn clash_udp_default_must_not_be_widened() {
    let b = parse(br#"{"proxies":[{"name":"test","type":"ss","server":"host.invalid","port":443,"cipher":"aes-128-gcm","password":"fixture"}]}"#,ImportFormat::ClashNodes).unwrap();
    assert_eq!(
        b.entries[0].diagnostics[0].kind,
        IssueKind::UnsupportedFeature
    );
}
#[test]
fn yaml_and_unlocked_tuic_uri_are_not_claimed_supported() {
    assert_eq!(
        parse(b"proxies:\n- name: fixture", ImportFormat::ClashNodes)
            .unwrap_err()
            .kind,
        IssueKind::UnsupportedFormat
    );
    assert_eq!(
        rejection("tuic://fixture@host.invalid:443").kind,
        IssueKind::UnsupportedScheme
    );
}
#[test]
fn json_duplicate_fields_even_nested_are_rejected() {
    assert_eq!(
        parse(
            br#"{"outbounds":[],"outbounds":[]}"#,
            ImportFormat::SingBoxOutbounds
        )
        .unwrap_err()
        .kind,
        IssueKind::DuplicateField
    );
    assert_eq!(
        parse(
            br#"{"outbounds":[{"tls":{"insecure":false,"insecure":true}}]}"#,
            ImportFormat::SingBoxOutbounds
        )
        .unwrap_err()
        .kind,
        IssueKind::DuplicateField
    );
}
#[test]
fn json_deeply_nested_input_is_bounded() {
    let input = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    let input = format!("{{\"outbounds\":{input}}}");
    assert_eq!(
        parse(input.as_bytes(), ImportFormat::SingBoxOutbounds)
            .unwrap_err()
            .kind,
        IssueKind::InputLimit
    );
}
#[test]
fn secret_boundaries_and_report_are_redacted() {
    let b = parse(b"hy2://unique-fixture-secret@host.invalid?obfs=salamander&obfs-password=unique-obfs-secret",ImportFormat::NodeUri).unwrap();
    let debug = format!("{b:?}");
    assert!(!debug.contains("unique-fixture-secret"));
    assert!(!debug.contains("unique-obfs-secret"));
    let report = b.review_report();
    assert!(report.entries[0].node.is_none());
    assert!(report.entries[0].preview.is_some());
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("unique-fixture-secret"));
    assert!(!json.contains("unique-obfs-secret"));
    assert!(!json.contains("secret:"));
    assert_eq!(
        report.entries[0].disposition,
        ImportDisposition::NeedsReview
    );
}
#[test]
fn obfuscation_binding_mismatch_cannot_materialize() {
    let c = candidate("hy2://fixture@host.invalid?obfs=salamander&obfs-password=fixture-obfs");
    let err = c
        .materialize(
            NodeId::new("test").unwrap(),
            None,
            AllocatedSecrets {
                credential_ref: SecretRef::new("test").unwrap(),
                obfuscation_ref: None,
            },
        )
        .unwrap_err();
    assert_eq!(err.kind, IssueKind::SecretBindingMismatch);
}
#[test]
fn export_rejects_custom_trust_and_native_tls_fingerprint_loss() {
    let (mut n, s) = bind(candidate("anytls://fixture@host.invalid"));
    if let ClientSecurity::Tls { trust, .. } = &mut n.security {
        *trust = TlsTrust::CustomCa {
            certificate_ref: CertificateId::new("test-ca").unwrap(),
        };
    }
    let e = export_uri(&n, &s).unwrap_err();
    assert_eq!(e.kind, IssueKind::LossyExport);
    assert_eq!(e.error.stage, ErrorStage::Export);
    let (mut n, s) = bind(candidate(
        "vmess://00000000-0000-4000-8000-000000000001@host.invalid:443?security=tls",
    ));
    if let ClientSecurity::Tls {
        client_hello_fingerprint,
        ..
    } = &mut n.security
    {
        *client_hello_fingerprint = None;
    }
    assert_eq!(export_uri(&n, &s).unwrap_err().kind, IssueKind::LossyExport);
}
#[test]
fn legacy_vmess_aead_subset_is_distinct_from_modern_uri() {
    let source = r#"{"v":"2","ps":"Synthetic legacy","add":"host.invalid","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","scy":"auto","net":"ws","type":"none","host":"front.invalid","path":"/ws","tls":"tls","sni":"host.invalid","fp":"chrome"}"#;
    roundtrip(&format!("vmess://{}", STANDARD.encode(source)));
    let insecure = source.replace("\"aid\":\"0\"", "\"aid\":\"100\"");
    assert_eq!(
        rejection(&format!("vmess://{}", STANDARD.encode(insecure))).kind,
        IssueKind::UnsupportedFeature
    );
}
#[test]
fn export_debug_cannot_disclose_uri() {
    let (n, s) = bind(candidate("anytls://unique-fixture-secret@host.invalid"));
    let export = export_uri(&n, &s).unwrap();
    assert!(!format!("{export:?}").contains("unique-fixture-secret"));
    assert!(export.expose().contains("unique-fixture-secret"));
}

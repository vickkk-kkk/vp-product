#![allow(clippy::unwrap_used, clippy::expect_used)]
use vp_product_compiler::{server_v2::*, CompileFailure, Compiler, ExecutionRecipe};
use vp_product_domain::*;
fn release() -> ReleaseIdentity {
    ReleaseIdentity {
        release_id: ReleaseId::new("server-v2-source-test").unwrap(),
        product_version: "0.1-test".into(),
        adapter_version: "0.1-test".into(),
        core_commit: "a".repeat(40),
        patchset_hash: Some("b".repeat(64)),
        build_target: "x86_64-linux".into(),
        toolchain: "unit-only".into(),
        schema_read: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        schema_write: CompatibilityRange {
            minimum: 1,
            maximum: 1,
        },
        abi: VersionPair {
            major: ABI_MAJOR,
            minor: ABI_MINOR,
        },
        api: VersionPair { major: 1, minor: 0 },
        evidence_manifest_hash: None,
    }
}
fn tls(alpn: &[&str]) -> ServerSecurity {
    ServerSecurity::Tls {
        certificate_ref: CertificateId::new("certificate-version-1").unwrap(),
        private_key_ref: SecretRef::new("key-version-1").unwrap(),
        alpn: alpn.iter().map(|s| (*s).into()).collect(),
    }
}
fn config(key: CapabilityKey) -> ProductConfig {
    use CapabilityKey as K;
    let protocol = match key {
        K::Tuic => Protocol::Tuic {
            congestion_control: CongestionControl::Bbr,
            udp_relay_mode: TuicUdpRelayMode::Native,
        },
        K::Hysteria2 => Protocol::Hysteria2 {
            obfuscation_ref: None,
        },
        K::TrojanTls | K::TrojanH2Tls | K::TrojanWsTls | K::TrojanHttpUpgradeTls => {
            Protocol::Trojan {}
        }
        K::AnyTls => Protocol::AnyTls {},
        K::SocksAuth => Protocol::Socks5 {},
        K::Shadowsocks => Protocol::Shadowsocks {
            method: ShadowsocksCipher::Blake3Aes128Gcm2022,
        },
        K::VlessRealityVision => Protocol::Vless {
            flow: Some(VlessFlow::XtlsRprxVision),
        },
        K::VlessH2Reality | K::VlessH2Tls | K::VlessWsTls | K::VlessHttpUpgradeTls => {
            Protocol::Vless { flow: None }
        }
        _ => Protocol::Vmess {
            cipher: VmessCipher::Auto,
            alter_id: 0,
        },
    };
    let transport = match key {
        K::Tuic | K::Hysteria2 | K::VmessQuic => Transport::Quic {},
        K::VmessWs | K::VmessWsTls | K::VlessWsTls | K::TrojanWsTls => Transport::Ws {
            path: "/test%2Froute".into(),
            host: Some("proxy.example.invalid:443".into()),
            early_data: None,
        },
        K::VmessHttp => Transport::Http {
            path: "/transport".into(),
            host: "proxy.example.invalid".into(),
        },
        K::VmessH2Tls | K::VlessH2Tls | K::TrojanH2Tls | K::VlessH2Reality => Transport::H2 {
            path: "/transport".into(),
            host: "proxy.example.invalid".into(),
        },
        K::VmessHttpUpgradeTls | K::VlessHttpUpgradeTls | K::TrojanHttpUpgradeTls => {
            Transport::HttpUpgrade {
                path: "/transport".into(),
                host: "proxy.example.invalid".into(),
            }
        }
        _ => Transport::Tcp {},
    };
    let security = match key {
        K::VmessWs | K::VmessTcp | K::VmessHttp | K::Shadowsocks | K::SocksAuth => {
            ServerSecurity::None {}
        }
        K::VlessRealityVision | K::VlessH2Reality => ServerSecurity::Reality {
            private_key_ref: SecretRef::new("reality-version-1").unwrap(),
            server_names: vec!["example.invalid".into()],
            short_ids: vec!["00".into()],
            handshake_target: Endpoint {
                host: "example.invalid".into(),
                port: 443,
            },
        },
        _ => tls(match transport {
            Transport::Tcp {} => &[],
            Transport::H2 { .. } => &["h2"],
            Transport::Quic {} => &["h3"],
            _ => &["http/1.1"],
        }),
    };
    ProductConfig {
        schema_version: 1,
        minimum_reader_version: 1,
        nodes: vec![],
        subscriptions: vec![],
        listeners: vec![ServerListener {
            schema_version: 1,
            id: ListenerId::new("listener-1").unwrap(),
            name: "source-only-test".into(),
            enabled: true,
            bind: BindAddress {
                address: "127.0.0.1".parse().unwrap(),
                port: 19001,
            },
            protocol: ServerProtocol::Proxy {
                protocol,
                users: vec![ListenerUser {
                    id: UserId::new("user-1").unwrap(),
                    credential_ref: SecretRef::new("credential-version-1").unwrap(),
                    enabled: true,
                }],
            },
            transport,
            security,
            requirements: vec![key],
        }],
    }
}
fn compile(c: &ProductConfig) -> Result<ServerRecipeV2, vp_product_compiler::CompileError> {
    ServerCompilerV2::for_loopback_development(release())
        .unwrap()
        .compile(c, &release())
}
#[test]
fn all_21_presets_remain_enumerated_with_15_exact_candidates_and_6_explicit_blockers() {
    use CapabilityKey::*;
    let mapped = [
        TrojanTls,
        Hysteria2,
        VmessWs,
        VmessTcp,
        Shadowsocks,
        VmessH2Tls,
        VmessWsTls,
        VlessH2Tls,
        VlessWsTls,
        TrojanH2Tls,
        TrojanWsTls,
        VmessHttpUpgradeTls,
        VlessHttpUpgradeTls,
        TrojanHttpUpgradeTls,
        AnyTls,
    ];
    let blocked = [
        Tuic,
        VmessHttp,
        VmessQuic,
        VlessRealityVision,
        VlessH2Reality,
        SocksAuth,
    ];
    assert_eq!(mapped.len() + blocked.len(), 21);
    for key in mapped {
        let result = compile(&config(key)).unwrap();
        assert_eq!(result.listeners[0].capability, Some(key));
    }
    for key in blocked {
        assert!(
            compile(&config(key)).is_err(),
            "no fake mapping for {key:?}"
        );
    }
}
#[test]
fn v1_pipeline_and_artifacts_are_not_implicitly_upgraded() {
    let c = config(CapabilityKey::VmessTcp);
    let v1 = Compiler::for_loopback_development(release())
        .unwrap()
        .compile(&c, &release())
        .unwrap();
    let v2 = compile(&c).unwrap();
    assert_eq!(v1.recipe_version, 1);
    assert_eq!(v2.recipe_version, 2);
    assert!(serde_json::from_value::<ExecutionRecipe>(serde_json::to_value(v2).unwrap()).is_err());
    assert!(serde_json::from_value::<ServerRecipeV2>(serde_json::to_value(v1).unwrap()).is_err());
}
#[test]
fn tls_is_reference_only_and_alpn_is_exact_not_overwritten() {
    for key in [
        CapabilityKey::TrojanTls,
        CapabilityKey::AnyTls,
        CapabilityKey::Hysteria2,
        CapabilityKey::VmessH2Tls,
        CapabilityKey::VlessWsTls,
        CapabilityKey::TrojanHttpUpgradeTls,
    ] {
        let c = config(key);
        let recipe = compile(&c).unwrap();
        let ServerSecurity::Tls { alpn: input, .. } = &c.listeners[0].security else {
            panic!()
        };
        let ServerSecurityV2::Tls { alpn: output, .. } = &recipe.listeners[0].security else {
            panic!()
        };
        assert_eq!(input, output);
        let bytes = serde_json::to_string(&recipe).unwrap();
        assert!(!bytes.contains("BEGIN CERTIFICATE"));
        assert!(!bytes.contains("PRIVATE KEY"));
        let mut changed = c;
        if let ServerSecurity::Tls { alpn, .. } = &mut changed.listeners[0].security {
            alpn.push("not-the-requested-profile".into());
        }
        let error = compile(&changed).unwrap_err();
        assert_eq!(error.field_path, "listeners[0].security.alpn");
    }
}
#[test]
fn transport_carriers_remain_distinct_and_decode_route_once() {
    let ws = compile(&config(CapabilityKey::VmessWsTls)).unwrap();
    assert!(
        matches!(&ws.listeners[0].transport, ServerTransportV2::WebSocket { decoded_path, .. } if decoded_path=="/test/route")
    );
    let upgrade = compile(&config(CapabilityKey::VmessHttpUpgradeTls)).unwrap();
    assert!(matches!(
        upgrade.listeners[0].transport,
        ServerTransportV2::HttpUpgrade { .. }
    ));
    let h2 = compile(&config(CapabilityKey::VmessH2Tls)).unwrap();
    assert!(matches!(
        h2.listeners[0].transport,
        ServerTransportV2::Http2 { .. }
    ));
    let mut c = config(CapabilityKey::VmessWs);
    if let Transport::Ws { path, .. } = &mut c.listeners[0].transport {
        *path = "/one%252Ftwo".into();
    }
    assert!(
        matches!(&compile(&c).unwrap().listeners[0].transport, ServerTransportV2::WebSocket { decoded_path, .. } if decoded_path=="/one%2Ftwo")
    );
}
#[test]
fn early_data_http1_quic_vision_obfuscation_and_socks_auth_cannot_disappear() {
    let mut c = config(CapabilityKey::VmessWs);
    if let Transport::Ws { early_data, .. } = &mut c.listeners[0].transport {
        *early_data = Some(EarlyData {
            max_bytes: 2048,
            header_name: "Sec-WebSocket-Protocol".into(),
        });
    }
    assert_eq!(
        compile(&c).unwrap_err().field_path,
        "listeners[0].transport.earlyData"
    );
    let mut c = config(CapabilityKey::Hysteria2);
    if let ServerProtocol::Proxy { protocol, .. } = &mut c.listeners[0].protocol {
        *protocol = Protocol::Hysteria2 {
            obfuscation_ref: Some(SecretRef::new("obfs-version-1").unwrap()),
        };
    }
    assert_eq!(
        compile(&c).unwrap_err().field_path,
        "listeners[0].protocol.protocol.obfuscationRef"
    );
    for key in [
        CapabilityKey::VmessHttp,
        CapabilityKey::VmessQuic,
        CapabilityKey::VlessRealityVision,
        CapabilityKey::SocksAuth,
    ] {
        assert!(compile(&config(key)).is_err());
    }
}
#[test]
fn secret_payload_encoding_is_explicit_and_all_seven_ss_methods_preserved() {
    for method in ShadowsocksCipher::ALL {
        let mut c = config(CapabilityKey::Shadowsocks);
        if let ServerProtocol::Proxy { protocol, .. } = &mut c.listeners[0].protocol {
            *protocol = Protocol::Shadowsocks { method };
        }
        let r = compile(&c).unwrap();
        assert_eq!(
            r.listeners[0].protocol,
            ServerProtocolV2::Shadowsocks { method }
        );
        assert_eq!(
            matches!(
                r.listeners[0].credentials[0].encoding,
                CredentialEncodingV2::Shadowsocks2022PskBase64V1 { .. }
            ),
            method.is_2022()
        );
    }
    assert!(matches!(
        compile(&config(CapabilityKey::AnyTls)).unwrap().listeners[0].credentials[0].encoding,
        CredentialEncodingV2::PasswordUtf8V1 {}
    ));
    assert!(matches!(
        compile(&config(CapabilityKey::VmessTcp)).unwrap().listeners[0].credentials[0].encoding,
        CredentialEncodingV2::CanonicalUuidTextV1 {}
    ));
}
#[test]
fn hy2_and_ss_multiuser_are_not_truncated() {
    for key in [CapabilityKey::Hysteria2, CapabilityKey::Shadowsocks] {
        let mut c = config(key);
        if let ServerProtocol::Proxy { users, .. } = &mut c.listeners[0].protocol {
            let mut user = users[0].clone();
            user.id = UserId::new("user-2").unwrap();
            users.push(user);
        }
        assert_eq!(
            compile(&c).unwrap_err().field_path,
            "listeners[0].protocol.users"
        );
    }
}
#[test]
fn exact_recompile_rejects_modified_materialization_and_release() {
    let mut recipe = compile(&config(CapabilityKey::TrojanTls)).unwrap();
    recipe.listeners[0].bind.port += 1;
    let compiler = ServerCompilerV2::for_loopback_development(release()).unwrap();
    assert!(compiler.verify_recipe(&recipe).is_err());
    let mut recipe = compile(&config(CapabilityKey::TrojanTls)).unwrap();
    recipe.recipe_version = 1;
    assert!(compiler.verify_recipe(&recipe).is_err());
    let mut altered = release();
    altered.patchset_hash = Some("c".repeat(64));
    assert_eq!(
        compiler
            .compile(&config(CapabilityKey::TrojanTls), &altered)
            .unwrap_err()
            .code,
        CompileFailure::ReleaseMismatch
    );
}
#[test]
fn malformed_http_authority_paths_and_unknown_fields_are_rejected() {
    for invalid in [
        "user@host.invalid",
        "host.invalid:abc",
        "::1",
        "host.invalid/path",
        "[bad]:443",
    ] {
        let mut c = config(CapabilityKey::VmessWs);
        if let Transport::Ws { host, .. } = &mut c.listeners[0].transport {
            *host = Some(invalid.into());
        }
        assert!(compile(&c).is_err());
    }
    for invalid in [
        "/bad%ZZ",
        "/bad%00",
        "/path?secret=query",
        "/path#fragment",
        "/space%20here",
    ] {
        let mut c = config(CapabilityKey::VmessWs);
        if let Transport::Ws { path, .. } = &mut c.listeners[0].transport {
            *path = invalid.into();
        }
        assert!(compile(&c).is_err());
    }
    let mut value =
        serde_json::to_value(compile(&config(CapabilityKey::TrojanTls)).unwrap()).unwrap();
    value["listeners"][0]["security"]["privateKeyPem"] = "forbidden".into();
    assert!(serde_json::from_value::<ServerRecipeV2>(value).is_err());
}
#[test]
fn per_listener_bind_and_disabled_metadata_are_preserved_without_public_execution() {
    let mut c = config(CapabilityKey::VmessTcp);
    let mut second = c.listeners[0].clone();
    second.id = ListenerId::new("second").unwrap();
    second.bind.address = "::1".parse().unwrap();
    second.bind.port += 1;
    c.listeners.push(second);
    let recipe = compile(&c).unwrap();
    assert_eq!(
        recipe.listeners[1].bind.address,
        "::1".parse::<std::net::IpAddr>().unwrap()
    );
    c.listeners[1].enabled = false;
    let recipe = compile(&c).unwrap();
    assert_eq!(recipe.listeners.len(), 1);
    assert_eq!(recipe.source.listeners.len(), 2);
    c.listeners[0].bind.address = "0.0.0.0".parse().unwrap();
    assert_eq!(
        compile(&c).unwrap_err().code,
        CompileFailure::LoopbackRequired
    );
}

fn compile_extended(
    config: &ProductConfig,
) -> Result<ServerRecipeV2, vp_product_compiler::CompileError> {
    ServerCompilerV2::for_loopback_server_extensions(release())
        .unwrap()
        .compile(config, &release())
}
#[test]
fn extended_profile_has_seventeen_source_paths_not_twenty_one_certifications() {
    use CapabilityKey::*;
    let mapped = [
        Tuic,
        TrojanTls,
        Hysteria2,
        VmessWs,
        VmessTcp,
        Shadowsocks,
        VmessH2Tls,
        VmessWsTls,
        VlessH2Tls,
        VlessWsTls,
        TrojanH2Tls,
        TrojanWsTls,
        VmessHttpUpgradeTls,
        VlessHttpUpgradeTls,
        TrojanHttpUpgradeTls,
        AnyTls,
        SocksAuth,
    ];
    let blocked = [VmessHttp, VmessQuic, VlessRealityVision, VlessH2Reality];
    assert_eq!(mapped.len() + blocked.len(), 21);
    for preset in mapped {
        assert!(compile_extended(&config(preset)).is_ok(), "{preset:?}");
    }
    for preset in blocked {
        assert!(compile_extended(&config(preset)).is_err(), "{preset:?}");
    }
}
#[test]
fn all_tuic_options_are_exact_and_use_typed_tuple_material() {
    for congestion_control in [
        CongestionControl::Cubic,
        CongestionControl::NewReno,
        CongestionControl::Bbr,
    ] {
        for udp_relay_mode in [TuicUdpRelayMode::Native, TuicUdpRelayMode::Quic] {
            let mut c = config(CapabilityKey::Tuic);
            let ServerProtocol::Proxy { protocol, .. } = &mut c.listeners[0].protocol else {
                unreachable!()
            };
            *protocol = Protocol::Tuic {
                congestion_control,
                udp_relay_mode,
            };
            let recipe = compile_extended(&c).unwrap();
            assert_eq!(
                recipe.listeners[0].protocol,
                ServerProtocolV2::Tuic {
                    congestion_control,
                    udp_relay_mode
                }
            );
            assert_eq!(
                recipe.listeners[0].credentials[0].encoding,
                CredentialEncodingV2::TuicUuidPasswordJsonV1 {}
            );
            assert!(compile(&c).is_err());
        }
    }
}
#[test]
fn socks_is_authenticated_raw_tcp_only_and_cannot_reinterpret_v1_credential() {
    let mut c = config(CapabilityKey::SocksAuth);
    let recipe = compile_extended(&c).unwrap();
    assert_eq!(
        recipe.listeners[0].protocol,
        ServerProtocolV2::Socks5Authenticated {}
    );
    assert_eq!(
        recipe.listeners[0].credentials[0].encoding,
        CredentialEncodingV2::SocksUsernamePasswordJsonV1 {}
    );
    assert!(compile(&c).is_err());
    c.listeners[0].security = tls(&[]);
    assert!(compile_extended(&c).is_err());
}
#[test]
fn extended_exact_alpn_is_ordered_and_profile_cannot_be_downgraded() {
    let mut c = config(CapabilityKey::TrojanTls);
    c.listeners[0].security = tls(&["protocol-b", "protocol-a"]);
    let recipe = compile_extended(&c).unwrap();
    assert!(
        matches!(&recipe.listeners[0].security,ServerSecurityV2::Tls {alpn,..} if alpn==&["protocol-b","protocol-a"])
    );
    assert!(compile(&c).is_err());
    let compiler = ServerCompilerV2::for_loopback_server_extensions(release()).unwrap();
    let mut altered = recipe.clone();
    altered.profile = ServerProfileV2::LoopbackDevelopmentUncertified;
    assert!(compiler.verify_recipe(&altered).is_err());
    for alpn in [vec!["h2", "h2"], vec!["bad\n"], vec![""]] {
        c.listeners[0].security = tls(&alpn);
        assert!(compile_extended(&c).is_err());
    }
    c = config(CapabilityKey::TrojanH2Tls);
    c.listeners[0].security = tls(&["http/1.1"]);
    assert!(compile_extended(&c).is_err());
}

#[test]
fn public_experiment_is_explicit_bounded_and_rejects_unsafe_plans() {
    let target = "8.8.8.8:443".parse().unwrap();
    assert!(ServerCompilerV2::for_public_experiment(release(), vec![]).is_err());
    assert!(ServerCompilerV2::for_public_experiment(release(), vec!["127.0.0.1:443".parse().unwrap()]).is_err());
    assert!(ServerCompilerV2::for_public_experiment(release(), vec![target, target]).is_err());
    let compiler = ServerCompilerV2::for_public_experiment(release(), vec![target]).unwrap();
    for key in [CapabilityKey::TrojanTls, CapabilityKey::VlessWsTls, CapabilityKey::VmessWsTls] {
        let mut c = config(key);
        assert!(compiler.compile(&c, &release()).is_err(), "public profile requires a specific non-loopback bind");
        c.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
        let recipe = compiler.compile(&c, &release()).unwrap();
        assert_eq!(recipe.profile, ServerProfileV2::PublicExperimentalUncertified);
        assert_eq!(recipe.public_targets.as_ref().unwrap(), &vec![target]);
        assert!(compiler.verify_recipe(&recipe).is_ok());
        let mut tampered = recipe.clone();
        tampered.public_targets = Some(vec!["1.1.1.1:443".parse().unwrap()]);
        assert!(compiler.verify_recipe(&tampered).is_err());
    }
    let mut ss = config(CapabilityKey::Shadowsocks);
    ss.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    assert!(compiler.compile(&ss, &release()).is_err(), "2022 cipher is not yet accepted in the experiment");
    if let ServerProtocol::Proxy { protocol, .. } = &mut ss.listeners[0].protocol {
        *protocol = Protocol::Shadowsocks { method: ShadowsocksCipher::Aes128Gcm };
    } else { panic!("expected proxy listener"); }
    assert!(compiler.compile(&ss, &release()).is_ok());
    let mut unsupported = config(CapabilityKey::VmessTcp);
    unsupported.listeners[0].bind.address = "192.168.1.5".parse().unwrap();
    assert!(compiler.compile(&unsupported, &release()).is_err());
    let compiler = ServerCompilerV2::for_public_experiment(release(), vec!["192.168.1.5:443".parse().unwrap()]);
    assert!(compiler.is_err());
}

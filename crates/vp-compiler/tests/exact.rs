#![allow(clippy::unwrap_used, clippy::expect_used)]
use vp_product_compiler::*;
use vp_product_domain::*;
fn release() -> ReleaseIdentity {
    ReleaseIdentity {
        release_id: ReleaseId::new("compiler-unit").unwrap(),
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
        abi: VersionPair { major: 1, minor: 0 },
        api: VersionPair { major: 1, minor: 0 },
        evidence_manifest_hash: None,
    }
}
fn config() -> ProductConfig {
    serde_json::from_value(serde_json::json!({"schemaVersion":1,"minimumReaderVersion":1,"nodes":[],"subscriptions":[],"listeners":[{
        "schemaVersion":1,"id":"listener-1","name":"unit","enabled":true,"bind":{"address":"127.0.0.1","port":12001},
        "protocol":{"kind":"proxy","protocol":{"kind":"vless","flow":null},"users":[{"id":"user-1","credentialRef":"secret:immutable-version-1","enabled":true}]},
        "transport":{"kind":"tcp"},"security":{"kind":"none"},"requirements":[]
    }]})).unwrap()
}
fn compile(config: &ProductConfig) -> Result<ExecutionRecipe, CompileError> {
    Compiler::for_loopback_development(release())
        .unwrap()
        .compile(config, &release())
}
#[test]
fn reference_only_recipe_roundtrip_retains_original_and_is_explicitly_uncertified() {
    let source = config();
    let recipe = compile(&source).unwrap();
    assert_eq!(recipe.source, source);
    assert_eq!(
        recipe.profile,
        ExecutionProfile::LoopbackDevelopmentUncertified
    );
    let bytes = serde_json::to_vec(&recipe).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("secret:immutable-version-1"));
    let restored = serde_json::from_slice(&bytes).unwrap();
    Compiler::for_loopback_development(release())
        .unwrap()
        .verify_recipe(&restored)
        .unwrap();
}
#[test]
fn exact_release_all_fields_and_missing_patchset_fail_closed() {
    let compiler = Compiler::for_loopback_development(release()).unwrap();
    let mut changed = release();
    changed.toolchain = "different".into();
    assert_eq!(
        compiler.compile(&config(), &changed).unwrap_err().code,
        CompileFailure::ReleaseMismatch
    );
    changed = release();
    changed.patchset_hash = None;
    assert!(Compiler::for_loopback_development(changed).is_err());
}
#[test]
fn unknown_and_security_extra_fields_rejected_before_compilation() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["listeners"][0]["security"]["skipVerify"] = true.into();
    assert!(serde_json::from_value::<ProductConfig>(value).is_err());
    let mut value = serde_json::to_value(config()).unwrap();
    value["listeners"][0]["unknown"] = true.into();
    assert!(serde_json::from_value::<ProductConfig>(value).is_err());
}
#[test]
fn tls_and_non_tcp_never_downgrade() {
    let mut source = config();
    source.listeners[0].security = ServerSecurity::Tls {
        certificate_ref: CertificateId::new("cert").unwrap(),
        private_key_ref: SecretRef::new("key-v1").unwrap(),
        alpn: vec!["h2".into()],
    };
    let error = compile(&source).unwrap_err();
    assert_eq!(error.code, CompileFailure::UnsupportedSecurity);
    assert_eq!(error.field_path, "listeners[0].security");
    source = config();
    source.listeners[0].transport = Transport::Ws {
        path: "/exact".into(),
        host: Some("test.invalid".into()),
        early_data: None,
    };
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::UnsupportedTransport
    );
}
#[test]
fn socks_auth_cannot_be_lowered_to_anonymous_builtin() {
    let mut source = config();
    if let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol {
        *protocol = Protocol::Socks5 {};
    }
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::UnsupportedProtocol
    );
}
#[test]
fn vmess_cipher_and_alter_id_must_match_worker_semantics() {
    let mut source = config();
    for (cipher, alter_id, accepted) in [
        (VmessCipher::Auto, 0, true),
        (VmessCipher::Aes128Gcm, 0, false),
        (VmessCipher::None, 0, false),
        (VmessCipher::Auto, 1, false),
    ] {
        if let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol {
            *protocol = Protocol::Vmess { cipher, alter_id };
        }
        assert_eq!(compile(&source).is_ok(), accepted);
    }
}
#[test]
fn all_seven_ss_methods_preserved_without_substitution() {
    let mut source = config();
    for method in ShadowsocksCipher::ALL {
        if let ServerProtocol::Proxy { protocol, .. } = &mut source.listeners[0].protocol {
            *protocol = Protocol::Shadowsocks { method };
        }
        assert_eq!(
            compile(&source).unwrap().listeners[0].protocol,
            RecipeProtocol::Shadowsocks { method }
        );
    }
}
#[test]
fn multiuser_ss_is_not_silently_reduced_to_one_password() {
    let mut source = config();
    if let ServerProtocol::Proxy { protocol, users } = &mut source.listeners[0].protocol {
        *protocol = Protocol::Shadowsocks {
            method: ShadowsocksCipher::Aes128Gcm,
        };
        let mut user = users[0].clone();
        user.id = UserId::new("second").unwrap();
        users.push(user);
    }
    assert_eq!(
        compile(&source).unwrap_err().field_path,
        "listeners[0].protocol.users"
    );
}
#[test]
fn unsupported_capability_hints_are_not_authority_and_disabled_entries_preserved() {
    let mut source = config();
    source.listeners[0].requirements = vec![CapabilityKey::VlessRealityVision];
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::UnsupportedCapability
    );
    source = config();
    let mut disabled = source.listeners[0].clone();
    disabled.id = ListenerId::new("disabled").unwrap();
    disabled.enabled = false;
    source.listeners.push(disabled);
    let recipe = compile(&source).unwrap();
    assert_eq!(recipe.listeners.len(), 1);
    assert_eq!(recipe.source.listeners.len(), 2);
}
#[test]
fn network_scope_shared_bind_duplicates_and_empty_runtime_reject_explicitly() {
    let mut source = config();
    source.listeners[0].bind.address = "0.0.0.0".parse().unwrap();
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::LoopbackRequired
    );
    source = config();
    let mut duplicate = source.listeners[0].clone();
    duplicate.id = ListenerId::new("second").unwrap();
    source.listeners.push(duplicate);
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::ConflictingBind
    );
    source.listeners[1].bind.address = "::1".parse().unwrap();
    source.listeners[1].bind.port += 1;
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::UnsupportedField
    );
    source = config();
    source.listeners[0].enabled = false;
    assert_eq!(
        compile(&source).unwrap_err().code,
        CompileFailure::NoEnabledListener
    );
}
#[test]
fn recipe_tampering_and_unknown_fields_rejected() {
    let mut recipe = compile(&config()).unwrap();
    recipe.listeners[0].port += 1;
    assert!(Compiler::for_loopback_development(release())
        .unwrap()
        .verify_recipe(&recipe)
        .is_err());
    let mut value = serde_json::to_value(recipe).unwrap();
    value["arbitraryCoreYaml"] = "forbidden".into();
    assert!(serde_json::from_value::<ExecutionRecipe>(value).is_err());
}

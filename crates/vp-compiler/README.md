# Exact reference-only compiler

`Compiler::for_loopback_development(pinned_release)` is pure product logic: no
upstream crate, filesystem, networking, secret resolution or runtime claims.
`compile(ProductConfig, ReleaseIdentity)` returns a serializable reference-only
`ExecutionRecipe`; errors carry a safe exact field path and typed rejection.
Unknown nested JSON fields are rejected by the domain DTO before compilation.

The current **uncertified loopback development** recipe maps:

- VLESS / TCP / no security / no flow; enabled UUID references are retained.
- VMess / TCP / no security / Auto cipher / alterId=0 only.
- Shadowsocks / TCP / no security / exactly one enabled immutable secret reference,
  preserving all seven cipher names. Actual cipher correctness is a separate core
  interoperability gate; compilation is not certification.

No SOCKS-auth to anonymous conversion, TLS removal, Vision downgrade, WebSocket to
TCP replacement, cipher substitution, unknown capability hint, mixed bind address,
non-loopback bind, duplicate enabled port, outbound node/subscription discard or
empty runtime is allowed. Disabled listeners and all metadata remain in the
artifact's original source config, while only enabled users/listeners execute.
Unsupported combinations are explicitly rejected even if disabled. Requirements
are hints: the compiler derives semantics, and rejects contradictory hints.

The target full release identity, schema/API/ABI and non-null patchset are pinned.
`verify_recipe` recompiles a durable artifact and compares every field; an artifact
cannot add a shell path, YAML escape hatch or arbitrary worker command.

This limited execution profile does **not** reduce the required release scope:
all 21 presets, seven SS methods, unresolved Direct scope and all native platform
acceptance remain tracked separately. Multi-bind, production vaults, TLS assets,
full transport/preset mappings, and whole-product acceptance remain incomplete.

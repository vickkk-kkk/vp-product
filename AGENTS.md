# Engineering conventions

## Repository boundaries

- Read README.md and docs/architecture.md first. This source snapshot contains the client submodule, server baseline, administration Web and installation tooling. Source inclusion is not build or runtime acceptance.
- `client/` is a real Git submodule. Make client changes in its fork, review and commit there, then update the parent gitlink to an exact commit. Never vendor a second active client or follow a floating branch silently.
- Reconstruct `integration/vp_core` from the exact core lock and ordered patches before Cargo resolution; see tools/core/README.md. Do not vendor caches or silently update pins.
- Keep the server Cargo workspace and existing relative paths intact until a separately reviewed migration verifies dependency resolution, tests and packaging.
- Keep only the administration Web app and its required shared packages. Do not reintroduce the legacy Flutter client as another active product client.

## Correctness and evidence

- Preserve upstream serialized formats and explicit compatibility boundaries. Unknown or unsupported security-sensitive fields must fail visibly.
- Keep pure domain logic separate from network access, process execution, filesystem policy and native VPN lifecycle.
- Coordinate manifests, lockfiles, domain types and generated contracts through one integrator per change.
- Distinguish static checks, compilation, unit tests, real engine traffic and platform acceptance. Record exact commands, source identity, environment and results; never relabel mock or another engine's output as runtime proof.
- Preserve the vp_core server boundary. Client multi-engine adapters must remain explicit; do not silently switch or fall back.

## Safety and source hygiene

- Do not commit real subscriptions, credentials, private keys, runtime databases, private notes, internal work histories, SDKs, caches or generated binaries.
- Public test-key fixtures require explicit source provenance, license retention and clear non-production labeling; they do not authorize inclusion of real keys.
- Preserve upstream licenses and notices. A component's license does not automatically license the whole product.
- Building does not authorize installers, service hooks, production deployment, signing, or changes to host routes, firewall, DNS, proxy or TUN settings.
- Do not publish or push changes without the applicable task authorization. Repository guidance is not authorization to expand scope.

## Documentation

Use concise Chinese for product-facing documentation. Describe paths that actually exist in the relevant commit; distinguish local preparation, remote publication and verified behavior. Do not publish private workspace paths or historical approval records. Keep relative links valid for the committed tree.

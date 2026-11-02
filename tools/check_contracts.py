#!/usr/bin/env python3
"""Rebuild wire schema, check drift, and validate structural contract fixtures.

Requires the pinned Rust toolchain and jsonschema==4.26.0. This is structural
contract validation, not a replacement for Rust cross-field/runtime validation.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
from importlib.metadata import version
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/schema/v1.schema.json"


def check_shape(generated, reviewed, path):
    """Catch renamed/missing properties even when an intersection is unsatisfiable."""
    if not isinstance(generated, dict) or not isinstance(reviewed, dict):
        return
    if "properties" in generated and "properties" in reviewed:
        assert set(generated["properties"]) == set(reviewed["properties"]), path
        for key in generated["properties"]:
            check_shape(generated["properties"][key], reviewed["properties"][key], path + "/" + key)
    def variants(schema):
        result = {}
        for member in schema.get("oneOf", []):
            tag = member.get("properties", {}).get("kind", {})
            if "const" in tag:
                result[tag["const"]] = member
            elif len(tag.get("enum", [])) == 1:
                result[tag["enum"][0]] = member
        return result
    a, b = variants(generated), variants(reviewed)
    if a and b:
        assert set(a) == set(b), path
        for tag in a:
            check_shape(a[tag], b[tag], path + "/" + tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Regenerate the committed artifact after reviewing source DTO/refinement changes")
    args = parser.parse_args()
    assert version("jsonschema") == "4.26.0", "Use the pinned contract checker dependency"
    output = subprocess.check_output(["cargo", "run", "--locked", "--quiet", "-p", "vp-product-domain", "--example", "export_schema"], cwd=ROOT)
    generated = json.loads(output)
    Draft202012Validator.check_schema(generated)
    defs = generated["$defs"]
    for name, definition in defs.items():
        for refinement in definition.get("allOf", []):
            check_shape(definition, refinement, name)

    def refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                yield value["$ref"]
            for child in value.values():
                yield from refs(child)
        elif isinstance(value, list):
            for child in value:
                yield from refs(child)
    for ref in refs(generated):
        assert ref.startswith("#/$defs/") and ref.split("/")[-1] in defs, ref
    for path in [ROOT / "contracts/events/v1.schema.json", ROOT / "contracts/openapi/v1.yaml"]:
        for ref in refs(json.loads(path.read_text())):
            if ref.startswith("../schema/v1.schema.json#/$defs/"):
                assert ref.rsplit("/", 1)[1] in defs, ref
            elif not ref.startswith("#/"):
                raise AssertionError("Unexpected external reference: " + ref)

    def validator(name):
        return Draft202012Validator({"$schema": generated["$schema"], "$defs": defs, "$ref": "#/$defs/" + name})
    fixtures = {
        "node-vless-reality.json": "NodeProfile",
        "runtime-idle.json": "RuntimeSnapshot",
        "event-resync.json": "RuntimeEvent",
        "config-empty.json": "ProductConfig",
    }
    for filename, name in fixtures.items():
        value = json.loads((ROOT / "contracts/fixtures" / filename).read_text())
        validator(name).validate(value)
    rejected = json.loads((ROOT / "contracts/fixtures/node-inline-secret.rejected.json").read_text())
    assert not validator("NodeProfile").is_valid(rejected)
    catalog = json.loads((ROOT / "contracts/capabilities/presets.json").read_text())
    validator("PresetCatalog").validate(catalog)
    assert len(catalog["presets"]) == 22
    assert sum(p["scope"] == "required_public_baseline" for p in catalog["presets"]) == 21
    assert all(p["status"] == "blocked" for p in catalog["presets"])

    for name, kinds in {"Protocol": ["trojan", "anytls", "socks5"], "Transport": ["tcp", "quic"], "ClientSecurity": ["none"], "ServerSecurity": ["none"], "TlsTrust": ["system"], "ConnectionIntent": ["disconnected"]}.items():
        for kind in kinds:
            value = {"kind": kind}
            validator(name).validate(value)
            value["securityOverride"] = "disable-tls"
            assert not validator(name).is_valid(value), (name, kind)
    assert not validator("Revision").is_valid(9007199254740992)
    assert not validator("SecretRef").is_valid("/tmp/credential")
    for name in ["NodeId", "ListenerId", "DraftId", "IdempotencyKey", "SafeCode"]:
        assert not validator(name).is_valid("/tmp/untrusted"), name
    assert not validator("PreviewProtocol").is_valid({"kind": "hysteria2", "obfuscationRef": "secret:must-not-leak"})
    validator("PreviewProtocol").validate({"kind": "hysteria2", "obfuscationRef": None})

    # A generated enum can be accidentally narrowed by an older inline review
    # refinement. Check every real public error through the full intersected DTO.
    for code in defs["ErrorCode"]["enum"]:
        validator("ProductError").validate({
            "code": code, "messageKey": "error.action_failed", "safeArgs": {},
            "fieldPath": None, "retryable": False, "stage": "export",
            "capabilityKey": None, "remediation": None, "diagnosticId": None,
        })
    for name, payload in {
        "CredentialCreatePayload": {"kind": {"kind": "uuid"}, "confirmGenerate": True},
        "CredentialRetirePayload": {"confirmRetire": True},
        "PublicationIssuePayload": {"expiresInSeconds": 300, "confirmIssueSecretUrl": True},
        "PublicationRevokePayload": {"confirmRevokeAccess": True},
    }.items():
        validator(name).validate(payload)
        confirmation = next(key for key in payload if key.startswith("confirm"))
        invalid = dict(payload, **{confirmation: False})
        assert not validator(name).is_valid(invalid), name
        invalid = dict(payload)
        del invalid[confirmation]
        assert not validator(name).is_valid(invalid), name
    assert not validator("PublicationIssuePayload").is_valid({"expiresInSeconds": 299, "confirmIssueSecretUrl": True})
    assert not validator("PublicationIssuePayload").is_valid({"expiresInSeconds": 2592001, "confirmIssueSecretUrl": True})

    if args.write:
        SCHEMA.write_bytes(output)
    assert SCHEMA.read_bytes() == output, "Generated schema drift; review DTO/refinements and run tools/check_contracts.py --write"
    print(f"PASS: {len(defs)} generated/reviewed definitions; no schema drift; references, fixtures, negative security cases and 21-preset inventory checked.")
    print("Not covered: method execution, ABI linkage/ownership, protocol interoperability, native platforms or release certification.")


if __name__ == "__main__":
    main()

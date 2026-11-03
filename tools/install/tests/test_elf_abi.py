import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_elf_abi as abi

class ElfAbiTests(unittest.TestCase):
    def test_numeric_order_and_patch_component(self):
        sample = '  0x0010:   Name: GLIBC_2.9  Flags: none  Version: 2\n  0x0020:   Name: GLIBC_2.10  Flags: none  Version: 3\n  0x0030:   Name: GLIBC_2.3.4  Flags: none  Version: 4\n'
        self.assertEqual(abi.parse_glibc_versions(sample)['minimum'], '2.10')
    def test_unknown_and_absent_are_not_certified(self):
        self.assertEqual(abi.parse_glibc_versions('')['status'], 'no_numeric_glibc_requirement_found')
        sample = '  0x0010:   Name: GLIBC_ABI_DT_RELR  Flags: none  Version: 2\n'
        self.assertEqual(abi.parse_glibc_versions(sample)['status'], 'unknown_glibc_abi')
    def test_host_elf_inspection_is_read_only(self):
        path = Path('/bin/true')
        if not path.exists() or not Path('/usr/bin/readelf').exists():
            self.skipTest('host ELF/readelf unavailable')
        report = abi.inspect_reviewed_elf(path)
        self.assertEqual(len(report['sha256']), 64)
        self.assertIn(report['status'], ('glibc_floor_detected_not_execution_certified', 'unknown_glibc_abi', 'no_numeric_glibc_requirement_found'))

    def test_artifact_set_uses_highest_floor_and_exact_hashes(self):
        def report(version, ch):
            return {"status": "glibc_floor_detected_not_execution_certified", "minimum": version, "unknown": [], "sha256": ch * 64}
        result = abi.aggregate_artifact_glibc({"worker": report("2.39", "a"), "daemon": report("2.9", "b")})
        self.assertEqual(result["minimum"], "2.39")
        self.assertEqual(result["artifactSha256"], {"daemon": "b" * 64, "worker": "a" * 64})
    def test_artifact_set_fails_closed_on_unknown(self):
        for data in ({}, {"worker": {"status": "unknown_glibc_abi"}},
                     {"worker": {"status": "glibc_floor_detected_not_execution_certified", "minimum": "2.39", "unknown": [], "sha256": "bad"}}):
            with self.assertRaises(ValueError): abi.aggregate_artifact_glibc(data)

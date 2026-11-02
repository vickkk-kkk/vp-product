"""Synthetic structural fixtures only. No fixture ELF or web asset executes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_install as v
import vp_fresh_bundle as f


class FreshBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-fresh-bundle-test-')
        self.base = Path(self.temp.name)
        h = bytearray(64); h[:7] = b'\x7fELF\x02\x01\x01'
        h[16:18] = struct.pack('<H',3)
        h[18:20] = struct.pack('<H', 62 if v.host_arch() == 'x86_64' else 183)
        self.blobs = {f.DAEMON: bytes(h)+b'synthetic-daemon', f.WORKER: bytes(h)+b'synthetic-worker',
                      f.MAINTENANCE: bytes(h)+b'synthetic-maintenance',
                      'core-lock.json': v.canonical({'integration':{'commit':'e96584fb8c7a38aa2c24beb89dcf969e70c24c93'}}),
                      'web/index.html': b'TEST ONLY NOT A PANEL',
                      'contracts/capabilities/presets.json':b'{"testOnly":true}'}
        meta = {'artifactBindingVersion':1,'coreAbiMajor':1,'coreAbiMinor':1,
                'coreCommit':'e96584fb8c7a38aa2c24beb89dcf969e70c24c93',
                'executableSha256':v.digest(self.blobs[f.DAEMON]),'payloadRead':3,'payloadWrite':3,
                'profile':f.PROFILE,'runtimeAvailable':True,'runtimeJournalPayload':2,'sqlLayout':1,
                'vaultBindingKind':5,'workerSha256':v.digest(self.blobs[f.WORKER]),
                'publicationDelivery':True,'publicationNetworkPolicy':'explicit_same_origin_loopback',
                'explicitWebRoot':True,'managementApiVersion':1}
        self.m = {'schemaVersion':2,'profile':f.PROFILE,'releaseId':'synthetic-test-only',
                  'productVersion':'test','engine':'vp_core','architecture':v.host_arch(),
                  'files':[], 'coreLockSha256':v.digest(self.blobs['core-lock.json']),
                  'controlState':copy.deepcopy(f.CONTROL),'runtimeJournalPayload':2,'vaultBindingKind':5,
                  'hostRequirements':copy.deepcopy(f.HOST),'maintenance':copy.deepcopy(f.MAINTENANCE_CAPABILITY),
                  'compatibilityDescriptor':{'descriptorVersion':2,'metadata':meta,
                    'artifactSetDigest':v.digest(b'vp.fresh-artifact-set.v1\0'+v.canonical(meta)),
                    'createsState':False,'startsService':False}}
        self.records()
    def tearDown(self):
        self.temp.cleanup()
    def records(self):
        self.m['files'] = [{'path':n,'size':len(b),'sha256':v.digest(b),'executable':n.startswith('bin/')} for n,b in sorted(self.blobs.items())]
    def archive(self):
        path = self.base / ('fixture-'+str(len(list(self.base.iterdir())))+'.zip')
        with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_STORED) as z:
            for n,b in {**self.blobs,'manifest.json':v.canonical(self.m)}.items():
                info=zipfile.ZipInfo(n); info.create_system=3;info.external_attr=0o100644<<16
                z.writestr(info,b)
        return path,v.digest(path.read_bytes())
    def reject(self):
        with self.assertRaises(v.InstallError):
            with f.FreshBundle(*self.archive()): pass
    def test_valid_synthetic_structure(self):
        with f.FreshBundle(*self.archive()) as b:
            self.assertEqual(b.manifest,self.m)
            b.extract(self.base/'extracted')
            self.assertEqual((self.base/'extracted'/f.DAEMON).read_bytes(),self.blobs[f.DAEMON])
    def test_ancestor_file_collision(self):
        self.blobs['web/collision']=b'a';self.blobs['web/collision/child']=b'b';self.records();self.reject()
    def test_web_file_limit(self):
        next(x for x in self.m['files'] if x['path']=='web/index.html')['size']=33*1024*1024
        self.reject()
    def test_web_directory_depth(self):
        self.blobs['web/'+'a/'*33+'file']=b'a';self.records();self.reject()
    def test_web_count_includes_directories(self):
        for i in range(2050):self.blobs['web/dir'+str(i)+'/file']=b'a'
        self.records();self.reject()
    def test_v1_reader_rejects_v2(self):
        with self.assertRaises(v.InstallError):v.Bundle(*self.archive())
    def test_unknown_top_field(self):self.m['upgrade']=True;self.reject()
    def test_old_descriptor_rejected(self):self.m['compatibilityDescriptor']['descriptorVersion']=1;self.reject()
    def test_missing_publication_capability(self):del self.m['compatibilityDescriptor']['metadata']['publicationDelivery'];self.reject()
    def test_wrong_profile(self):self.m['profile']='fresh-runtime.v1';self.reject()
    def test_old_payload(self):self.m['controlState']['payload']['writeVersion']=2;self.reject()
    def test_claimed_extra_reader(self):self.m['controlState']['payload']['readVersions']=[2,3];self.reject()
    def test_boolean_version(self):self.m['controlState']['sqlLayout']['writeVersion']=True;self.reject()
    def test_descriptor_unknown_field(self):self.m['compatibilityDescriptor']['metadata']['extra']=1;self.reject()
    def test_descriptor_stateful(self):self.m['compatibilityDescriptor']['createsState']=True;self.reject()
    def test_wrong_artifact_digest(self):self.m['compatibilityDescriptor']['artifactSetDigest']='0'*64;self.reject()
    def test_wrong_daemon(self):self.blobs[f.DAEMON]+=b'changed';self.records();self.reject()
    def test_wrong_worker(self):self.blobs[f.WORKER]+=b'changed';self.records();self.reject()
    def test_unknown_core(self):self.m['compatibilityDescriptor']['metadata']['coreCommit']='a'*40;self.reject()
    def test_false_core_lock(self):
        self.blobs['core-lock.json']=b'{"integration":{"commit":"other"}}';self.records()
        self.m['coreLockSha256']=v.digest(self.blobs['core-lock.json']);self.reject()
    def test_truncated_maintenance_elf(self):self.blobs[f.MAINTENANCE]=self.blobs[f.MAINTENANCE][:32];self.records();self.reject()
    def test_nonexecutable_elf_type(self):
        data=bytearray(self.blobs[f.MAINTENANCE]);data[16:18]=b'\0\0';self.blobs[f.MAINTENANCE]=bytes(data);self.records();self.reject()
    def test_no_maintenance(self):del self.blobs[f.MAINTENANCE];self.records();self.reject()
    def test_no_web(self):del self.blobs['web/index.html'];self.records();self.reject()
    def test_unlisted_member(self):self.blobs['extra']=b'x';self.reject()
    def test_unapproved_hook(self):self.blobs['bin/hook']=b'#!/bin/sh';self.records();self.reject()
    def test_maintenance_no_inspection_claim(self):self.m['maintenance']['controlInspectionSupported']=True;self.reject()
    def test_sealing_no_fallback(self):self.m['hostRequirements']['pathExecutionFallback']=True;self.reject()
    def test_digest_gate_before_parse(self):
        p,_=self.archive()
        with self.assertRaises(v.InstallError):f.FreshBundle(p,'0'*64)
    def test_reader_no_execution(self):
        with mock.patch('subprocess.Popen',side_effect=AssertionError('must not execute')):
            with f.FreshBundle(*self.archive()):pass
    def test_describe_preflight_before_execution(self):
        with mock.patch.object(f,'check_sealed_runtime_host',return_value={'prerequisitesAvailable':False}), mock.patch('subprocess.Popen',side_effect=AssertionError('must not execute')):
            with self.assertRaises(v.InstallError):f.describe(Path('/not-read'),'0'*64,Path('/not-read'),'0'*64)

if __name__=='__main__':unittest.main()

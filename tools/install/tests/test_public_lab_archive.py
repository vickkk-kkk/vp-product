"""Run against an explicitly provided local lab candidate archive, not a release test."""
import json, os, pathlib, socket, subprocess, tarfile, tempfile, unittest

@unittest.skipUnless(os.environ.get('VP_PUBLIC_LAB_CANDIDATE'), 'candidate archive not supplied')
class PublicLabArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vp-archive-test-')
        self.root = pathlib.Path(self.temp.name)
        with tarfile.open(os.environ['VP_PUBLIC_LAB_CANDIDATE'], 'r:gz') as archive:
            expected={'README.zh-CN.md','vp-lab','vp-public-lab','vp-core-server-worker-v2','manifest.json','NOT_FOR_DISTRIBUTION.txt'}
            self.assertEqual(set(archive.getnames()), expected)
            self.assertTrue(all(m.isfile() for m in archive.getmembers()))
            archive.extractall(self.root, filter='data')
        self.launcher=self.root/'vp-lab'
    def tearDown(self): self.temp.cleanup()
    def command(self, *args):
        return subprocess.run([str(self.launcher), *args], capture_output=True, text=True, timeout=30)
    def test_check_runs_and_does_not_claim_certification(self):
        result=self.command('check')
        self.assertEqual(result.returncode,0, result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['status'],'PREREQUISITES_PRESENT_NOT_EXECUTION_CERTIFIED')
        self.assertIs(report['testFixture'], False)
        self.assertFalse(report['startsListener'])
        self.assertFalse(report['writesState'])
    def test_run_reaches_confirmation_gate_without_creating_state(self):
        before=set(self.root.iterdir()); result=self.command('run')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('CONFIRMATION_REQUIRED',result.stderr)
        self.assertEqual(before,set(self.root.iterdir()))
    def test_full_run_arguments_reach_unassigned_bind_without_state(self):
        address='192.0.2.1'  # Reserved documentation address; no outbound traffic.
        check=socket.socket()
        try:
            try: check.bind((address,0))
            except OSError: pass
            else: self.skipTest('documentation address is assigned on this host')
        finally: check.close()
        session=self.root/'session'; session.mkdir(mode=0o700)
        result=self.command('run','--session-root',str(session),'--bind-ip',address,
            '--trojan-port','34111','--vless-port','34112','--ss-port','34113',
            '--confirm-test-access','--confirm-cloudflare-probe')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('BIND_UNAVAILABLE',result.stderr)
        self.assertEqual(list(session.iterdir()),[])
    def test_full_run_arguments_reach_occupied_port_check_without_state(self):
        route=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            route.connect(('192.0.2.1',9))  # No datagram is sent.
            ip=route.getsockname()[0]
        except OSError:
            self.skipTest('no assigned IPv4 route for the local fixture')
        finally: route.close()
        if ip.startswith('127.') or ip=='0.0.0.0': self.skipTest('no non-loopback local IPv4')
        occupied=socket.socket()
        try:
            occupied.bind((ip,0)); occupied.listen(); port=occupied.getsockname()[1]
            ports=[]
            for _ in range(2):
                spare=socket.socket(); spare.bind((ip,0)); ports.append(spare.getsockname()[1]); spare.close()
            if len({port,*ports})!=3: self.skipTest('fixture port allocation collision')
            session=self.root/'session'; session.mkdir(mode=0o700)
            result=self.command('run','--session-root',str(session),'--bind-ip',ip,
                '--trojan-port',str(port),'--vless-port',str(ports[0]),'--ss-port',str(ports[1]),
                '--confirm-test-access','--confirm-cloudflare-probe')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('BIND_UNAVAILABLE',result.stderr)
            self.assertEqual(list(session.iterdir()),[])
        finally: occupied.close()
    def test_tampering_and_unsafe_permissions_refused(self):
        worker=self.root/'vp-core-server-worker-v2';worker.chmod(0o722)
        self.assertNotEqual(self.command('check').returncode,0)
        worker.chmod(0o700)
        with worker.open('ab') as f: f.write(b'x')
        self.assertNotEqual(self.command('check').returncode,0)
    def test_unsafe_package_directory_refused(self):
        self.root.chmod(0o1777)
        self.assertNotEqual(self.command('check').returncode,0)
        self.root.chmod(0o700)

if __name__=='__main__': unittest.main()

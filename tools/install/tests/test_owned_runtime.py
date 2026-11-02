"""Supervisor ownership/race tests with explicit process and pidfd doubles only."""
import io
from pathlib import Path
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import vp_owned_runtime as r
from vp_install import InstallError

class OwnedRuntimeTests(unittest.TestCase):
    def make(self):
        owned=r.OwnedRuntime.__new__(r.OwnedRuntime)
        owned.process=mock.Mock();owned.process.poll.return_value=0;owned.process.returncode=0
        owned.process.stdin=io.BytesIO();owned.process.stdout=io.BytesIO();owned.process.stderr=io.BytesIO()
        owned.selector=mock.Mock();owned.ready=None
        owned.workers={(1,'a'):{'identity':{'pid':1,'start':'a'},'fd':101},
                       (2,'b'):{'identity':{'pid':2,'start':'b'},'fd':102}}
        owned.capture_workers=mock.Mock()
        return owned
    def test_esrch_does_not_skip_second_worker_or_close(self):
        owned=self.make();owned._worker_gone=mock.Mock(side_effect=[False,False,True])
        with mock.patch.object(r.signal,'pidfd_send_signal',side_effect=[ProcessLookupError(),None]) as send, mock.patch.object(r.os,'close') as close:
            result=owned.stop()
        self.assertEqual(send.call_count,2);self.assertEqual(close.call_args_list,[mock.call(101),mock.call(102)])
        self.assertTrue(result['stopped']);self.assertFalse(result['unobservedDescendantsCertified'])
        owned.selector.close.assert_called_once();self.assertTrue(owned.process.stdout.closed)
    def test_one_failure_still_cleans_remaining_handles(self):
        owned=self.make();owned._stop_worker=mock.Mock(side_effect=[PermissionError(),None])
        with mock.patch.object(r.os,'close') as close:
            with self.assertRaises(InstallError):owned.stop()
        self.assertEqual(owned._stop_worker.call_count,2);self.assertEqual(close.call_count,2)
        owned.selector.close.assert_called_once();self.assertEqual(owned.workers,{})
    def test_capture_failure_still_stops_owned_direct_child(self):
        owned=self.make();owned.capture_workers.side_effect=InstallError('foreign child');owned.process.poll.return_value=None
        owned._stop_worker=mock.Mock()
        with mock.patch.object(r.os,'close'):
            with self.assertRaises(InstallError):owned.stop()
        owned.process.terminate.assert_called_once();owned.process.wait.assert_called_once_with(timeout=30)
        self.assertEqual(owned._stop_worker.call_count,2)
    def test_changed_identity_never_signaled(self):
        owned=self.make();owned._worker_gone=mock.Mock(return_value=True)
        with mock.patch.object(r.signal,'pidfd_send_signal') as send,mock.patch.object(r.os,'close'):
            owned.stop()
        send.assert_not_called()
    def test_cancel_before_ready_never_pumps(self):
        owned=self.make();owned.pump=mock.Mock()
        with self.assertRaises(InstallError):owned.await_ready('a'*32,cancelled=lambda:True)
        owned.pump.assert_not_called()
    def test_direct_exit_before_ready_refused(self):
        owned=self.make();owned.pump=mock.Mock(return_value=1)
        with self.assertRaises(InstallError):owned.await_ready('a'*32)
    def test_repeated_stop_no_stale_pid_signal(self):
        owned=self.make();owned._worker_gone=mock.Mock(return_value=True)
        with mock.patch.object(r.signal,'pidfd_send_signal') as send,mock.patch.object(r.os,'close'):
            owned.stop();owned.stop()
        send.assert_not_called()

if __name__=='__main__':unittest.main()

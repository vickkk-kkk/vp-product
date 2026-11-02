"""Pure CLI consumer tests with explicit in-memory doubles; no service acceptance.
All URL data is synthetic and is never printed by this test runner.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vp_api
import vp_publications as pub
from vp_form import SchemaForm
from vp_install import InstallError


def summary(state='not_issued', revision=1, source_revision=1, security=None):
    return {'schemaVersion': 1, 'id': 'pub_test', 'revision': revision, 'name': 'Test publication',
            'enabled': True, 'format': 'uri_list', 'sourceRevision': source_revision,
            'sources': [{'listenerId': 'listener_test', 'userId': 'user_test',
                         'endpoint': {'host': '127.0.0.1', 'port': 19001},
                         'clientSecurity': security or {'kind': 'none'}}],
            'createdAt': 1000, 'updatedAt': 2000,
            'token': {'state': state, 'version': 0 if state == 'not_issued' else 1,
                      'issuedAt': None if state == 'not_issued' else 1000,
                      'expiresAt': None if state == 'not_issued' else 301000},
            'lastSuccessfulReadAt': None}


def credential():
    return {'schemaVersion': 1, 'id': 'credential_test', 'revision': 1, 'secretRef': 'secret:test_only_ref',
            'kind': {'kind': 'uuid'}, 'createdAt': 1000, 'state': 'available', 'displayKey': 'credential.managed'}


def inventory(supported=True):
    return {'schemaVersion': 1, 'supportedKinds': [{'kind': 'uuid'}] if supported else [], 'credentials': [credential()]}


def args(action, **kwargs):
    data = dict(action=action, request_key='test_stable', revision=1, publication_id='pub_test', credential_id='credential_test',
                source_revision=2, request_file=None, output=None, json=False, dry_run=False, schema=None,
                expires_in_seconds=300, show_secret_url=True, confirm_generate=True, confirm_retire=True,
                confirm_publish_connection_secrets=True, confirm_revoke_access=True)
    data.update(kwargs)
    return SimpleNamespace(**data)


class Terminal(io.StringIO):
    def isatty(self):
        return True


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.api = mock.Mock()
        self.out = io.StringIO(); self.err = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(contextlib.redirect_stdout(self.out))
        self.stack.enter_context(contextlib.redirect_stderr(self.err))
        self.stack.enter_context(mock.patch.object(sys.stdin, 'isatty', return_value=False))
    def tearDown(self):
        self.stack.close()
    def token_result(self):
        # A nonproduction synthetic bearer fixture; no listener serves this URL.
        return {'publication': summary('active', 2), 'displayOnce': True,
                'subscriptionUrl': 'http://127.0.0.1:19002/subscriptions/v1/pub_test/synthetic_nonproduction_token'}
    def test_uuid_generation_exact_api_and_safe_reference(self):
        self.api.request.side_effect = [{'revision': 1, 'config': None}, inventory()]
        self.api.command.return_value = credential()
        self.assertEqual(pub.run(self.api, args('credential-create')), 0)
        self.api.command.assert_called_once_with('/api/v1/credentials', 'credential_create', 'test_stable', 1,
                                                {'kind': {'kind': 'uuid'}, 'confirmGenerate': True})
        self.assertEqual(json.loads(self.out.getvalue())['secretRef'], 'secret:test_only_ref')
    def test_unsupported_uuid_generator_does_not_mutate_or_fallback(self):
        self.api.request.side_effect = [{'revision': 1, 'config': None}, inventory(False)]
        with self.assertRaises(InstallError):
            pub.run(self.api, args('credential-create'))
        self.api.command.assert_not_called()
    def test_credential_retirement_is_not_node_revocation(self):
        self.api.request.return_value = inventory()
        self.api.command.return_value = {**credential(), 'state': 'retired', 'displayKey': 'credential.retired', 'revision': 2}
        self.assertEqual(pub.run(self.api, args('credential-retire')), 0)
        self.api.command.assert_called_once_with('/api/v1/credentials/credential_test/retire', 'credential_retire',
                                                'test_stable', 1, {'confirmRetire': True}, etag=True)
        self.assertIn('不是撤销节点访问', self.err.getvalue())
    def test_uuid_picker_selects_existing_without_secretref_prompt(self):
        self.api.request.return_value = inventory()
        choose = pub.credential_picker(self.api, 1, 'wizard', 'vless')
        with mock.patch('builtins.input', return_value='1'):
            self.assertEqual(choose('listener.protocol.users[0].credentialRef'), 'secret:test_only_ref')
        self.api.command.assert_not_called()
    def test_uuid_picker_explicit_generation_stable_key(self):
        self.api.request.return_value = inventory()
        self.api.command.return_value = credential()
        choose = pub.credential_picker(self.api, 1, 'wizard', 'vless')
        with mock.patch('builtins.input', return_value='生成'):
            choose('listener.protocol.users[0].credentialRef')
            choose('listener.protocol.users[0].credentialRef')
        keys = [call.args[2] for call in self.api.command.call_args_list]
        self.assertEqual(keys[0], keys[1])
        self.assertTrue(keys[0].startswith('wizard-cred-'))
    def test_uuid_picker_never_replaces_password_protocol(self):
        with self.assertRaises(InstallError):
            pub.credential_picker(self.api, 1, 'wizard', 'trojan')('listener.credentialRef')
        self.api.request.assert_not_called(); self.api.command.assert_not_called()
    def test_schema_form_callback_prevents_manual_reference_entry(self):
        callback = mock.Mock(return_value='secret:test_only_ref')
        form = SchemaForm({'$defs': {'ServerListener': {}, 'SecretRef': {'type': 'string'}}},
                          ask=mock.Mock(side_effect=AssertionError('must not prompt')), credential_provider=callback)
        self.assertEqual(form.collect({'$ref': '#/$defs/SecretRef'}, 'listener.protocol.users[0].credentialRef'),
                         'secret:test_only_ref')
        callback.assert_called_once()
    def test_non_uuid_configure_keeps_existing_schema_reference_workflow(self):
        preset = next(p for p in vp_api.catalog() if p['protocol'] == 'trojan')
        self.api.request.side_effect = [[{'key': preset['key'], 'status': 'certified'}],
                                       {'revision': 1, 'config': None}]
        self.api.command.side_effect = [{'id': 'draft_test', 'revision': 1, 'baseRevision': 1}, {'valid': True},
                                       {'id': 'plan_test', 'planHash': '0' * 64, 'baseRevision': 1}]
        options = args('configure', dry_run=True, catalog=None, config=None)
        with mock.patch.object(sys.stdin, 'isatty', return_value=True), mock.patch('builtins.input', return_value=preset['id']), \
             mock.patch.object(vp_api, 'listener_wizard', return_value={'id': 'listener_test'}) as form:
            self.assertEqual(vp_api.configure(self.api, options), 0)
        self.assertIsNone(form.call_args.kwargs['credential_provider'])
    def test_create_delegates_source_revision_to_current_config(self):
        payload = {k: copy.deepcopy(summary()[k]) for k in ('name', 'enabled', 'format', 'sources')}
        payload['confirmPublishConnectionSecrets'] = True
        self.api.request.return_value = {'revision': 1, 'config': None}
        self.api.command.return_value = summary()
        with mock.patch.object(pub, 'read_regular', return_value=json.dumps(payload).encode()):
            self.assertEqual(pub.run(self.api, args('publication-create', request_file='unused.json')), 0)
        self.api.command.assert_called_once_with('/api/v1/publications', 'publication_create', 'test_stable', 1, payload)
    def test_update_full_replacement_preserves_client_security(self):
        security = {'kind': 'tls', 'serverName': 'node.example.invalid', 'alpn': ['h2'],
                    'trust': {'kind': 'spki_sha256', 'pins': ['synthetic-pin']}, 'clientHelloFingerprint': 'chrome'}
        before = summary(security=security)
        payload = {k: copy.deepcopy(before[k]) for k in ('name', 'enabled', 'format', 'sources')}
        payload.update(sourceRevision=2, confirmPublishConnectionSecrets=True)
        self.api.request.side_effect = [before, {'revision': 2, 'config': None}]
        self.api.command.return_value = summary(revision=2, source_revision=2, security=security)
        with mock.patch.object(pub, 'read_regular', return_value=json.dumps(payload).encode()):
            self.assertEqual(pub.run(self.api, args('publication-update', request_file='unused.json')), 0)
        self.api.command.assert_called_once_with('/api/v1/publications/pub_test', 'publication_replace', 'test_stable',
                                                1, payload, verb='PUT', etag=True)
        self.assertEqual(self.api.command.call_args.args[4]['sources'][0]['clientSecurity'], security)
    def test_republish_only_changes_pinned_revision_and_explicit_confirmation(self):
        before = summary('active')
        self.api.request.side_effect = [before, {'revision': 2, 'config': None}]
        self.api.command.return_value = summary('active', 2, 2)
        self.assertEqual(pub.run(self.api, args('publication-republish')), 0)
        call = self.api.command.call_args
        self.assertEqual(call.args[:4], ('/api/v1/publications/pub_test', 'publication_replace', 'test_stable', 1))
        self.assertEqual(call.args[4]['sources'], before['sources'])
        self.assertEqual(call.args[4]['sourceRevision'], 2)
        self.assertEqual(call.kwargs, {'verb': 'PUT', 'etag': True})
    def test_republish_requires_explicit_noninteractive_source_revision(self):
        self.api.request.side_effect = [summary(), {'revision': 2, 'config': None}]
        with self.assertRaises(InstallError):
            pub.run(self.api, args('publication-republish', source_revision=None))
        self.api.command.assert_not_called()
    def test_revision_conflict_never_rebases_or_retries(self):
        self.api.request.return_value = summary(revision=2)
        with self.assertRaises(InstallError):
            pub.run(self.api, args('publication-revoke', revision=1))
        self.api.command.assert_not_called()
    def test_source_revision_drift_never_rebases(self):
        self.api.request.side_effect = [summary(), {'revision': 3, 'config': None}]
        with self.assertRaises(InstallError):
            pub.run(self.api, args('publication-republish', source_revision=2))
        self.api.command.assert_not_called()
    def test_subscription_revoke_exact_delete_and_no_user_mutation(self):
        self.api.request.return_value = summary('active')
        self.api.command.return_value = summary('revoked', 2)
        self.assertEqual(pub.run(self.api, args('publication-revoke')), 0)
        self.api.command.assert_called_once_with('/api/v1/publications/pub_test/token', 'publication_token_revoke',
                                                'test_stable', 1, {'confirmRevokeAccess': True}, verb='DELETE', etag=True)
        self.assertIn('已下载的节点凭据', self.err.getvalue())
    def test_issue_refuses_redirected_stdout_before_mutation(self):
        with self.assertRaises(InstallError):
            pub.issue(self.api, args('publication-issue'), summary())
        self.api.command.assert_not_called()
    def test_issue_refuses_json_file_and_plan_even_on_terminal(self):
        for flags in ({'json': True}, {'output': 'never-created'}, {'request_file': 'never-read'}, {'dry_run': True}):
            with contextlib.redirect_stdout(Terminal()), self.assertRaises(InstallError):
                pub.issue(self.api, args('publication-issue', **flags), summary())
        self.api.command.assert_not_called()
    def test_expiry_bounds_refuse_before_issuance(self):
        for expiry in (None, 299, 2592001, True):
            with contextlib.redirect_stdout(Terminal()), self.assertRaises(InstallError):
                pub.issue(self.api, args('publication-issue', expires_in_seconds=expiry), summary())
        self.api.command.assert_not_called()
    def test_issue_requires_explicit_display_consent(self):
        with contextlib.redirect_stdout(Terminal()), self.assertRaises(InstallError):
            pub.issue(self.api, args('publication-issue', show_secret_url=False), summary())
        self.api.command.assert_not_called()
    def test_issue_displays_exactly_once_only_on_terminal(self):
        result = self.token_result(); url = result['subscriptionUrl']
        self.api.command.return_value = result
        terminal = Terminal()
        with contextlib.redirect_stdout(terminal):
            self.assertEqual(pub.issue(self.api, args('publication-issue'), summary()), 0)
        self.assertTrue(terminal.getvalue().count(url) == 1, 'single terminal display')
        self.assertTrue(url not in self.err.getvalue(), 'no diagnostic URL')
        self.assertTrue('subscriptionUrl' not in terminal.getvalue(), 'no JSON secret response')
        self.assertEqual(result, {})
        self.api.command.assert_called_once_with('/api/v1/publications/pub_test/token', 'publication_token_issue',
            'test_stable', 1, {'expiresInSeconds': 300, 'confirmIssueSecretUrl': True}, etag=True, sensitive=True)
        self.assertIn('不是手机可访问', self.err.getvalue())
    def test_rotate_uses_existing_issue_route_not_invented_endpoint(self):
        self.api.command.return_value = self.token_result()
        with contextlib.redirect_stdout(Terminal()):
            self.assertEqual(pub.issue(self.api, args('publication-rotate', expires_in_seconds=2592000), summary('active')), 0)
        self.assertEqual(self.api.command.call_args.args[1], 'publication_token_issue')
        self.assertEqual(self.api.command.call_args.args[4]['expiresInSeconds'], 2592000)
    def test_issue_does_not_silently_rotate_existing_url(self):
        with contextlib.redirect_stdout(Terminal()), self.assertRaises(InstallError):
            pub.issue(self.api, args('publication-issue'), summary('active'))
        self.api.command.assert_not_called()
    def test_unknown_result_only_reconciles_safe_metadata_no_new_key(self):
        self.api.command.side_effect = InstallError('API transport failed')
        self.api.request.return_value = summary('active', 2)
        with contextlib.redirect_stdout(Terminal()):
            self.assertEqual(pub.issue(self.api, args('publication-issue'), summary()), 3)
        self.api.command.assert_called_once()
        self.api.request.assert_called_once_with('GET', '/api/v1/publications/pub_test')
        self.assertIn('未自动重发', self.err.getvalue())
    def test_same_key_unavailable_does_not_mint_again(self):
        self.api.command.side_effect = InstallError('API HTTP 409: SECRET_RESULT_UNAVAILABLE')
        self.api.request.return_value = summary('active', 2)
        with contextlib.redirect_stdout(Terminal()):
            self.assertEqual(pub.issue(self.api, args('publication-rotate'), summary('active')), 3)
        self.api.command.assert_called_once()
        self.assertEqual(self.api.command.call_args.args[2], 'test_stable')
    def test_unknown_outcome_failed_metadata_does_not_claim_success(self):
        self.api.command.side_effect = InstallError('API transport failed')
        self.api.request.side_effect = InstallError('unavailable')
        with contextlib.redirect_stdout(Terminal()):
            self.assertEqual(pub.issue(self.api, args('publication-issue'), summary()), 3)
        self.api.command.assert_called_once(); self.api.request.assert_called_once()
    def test_malformed_secret_response_is_not_printed(self):
        result = self.token_result(); result['extra'] = 'not_allowed'
        url = result['subscriptionUrl']; self.api.command.return_value = result
        self.api.request.return_value = summary('active', 2)
        terminal = Terminal()
        with contextlib.redirect_stdout(terminal):
            self.assertEqual(pub.issue(self.api, args('publication-issue'), summary()), 3)
        self.assertTrue(url not in terminal.getvalue() + self.err.getvalue(), 'no malformed secret response leak')
    def test_terminal_loss_after_request_does_not_fallback(self):
        self.api.command.return_value = self.token_result()
        self.api.request.return_value = summary('active', 2)
        terminal = Terminal()
        with contextlib.redirect_stdout(terminal), mock.patch.object(terminal, 'isatty', side_effect=[True, False]):
            self.assertEqual(pub.issue(self.api, args('publication-issue'), summary()), 3)
        self.assertTrue('/subscriptions/v1/' not in terminal.getvalue(), 'no fallback secret output')
    def test_ordinary_metadata_rejects_secret_envelopes_and_unknown_fields(self):
        for value in (self.token_result(), {'token': 'synthetic'}, {'note': self.token_result()['subscriptionUrl']}):
            with self.assertRaises(InstallError):
                pub.emit(value)
        bad = summary(); bad['unexpected'] = 'value'
        with self.assertRaises(InstallError):
            pub.publication(bad)
        self.assertEqual(self.out.getvalue(), '')
    def test_source_security_unknown_fields_never_dropped(self):
        value = summary(); value['sources'][0]['clientSecurity']['insecure'] = True
        with self.assertRaises(InstallError):
            pub.publication(value)
    def test_list_expired_token_is_server_metadata_not_local_clock_guess(self):
        self.api.request.return_value = [summary('expired', 2)]
        self.assertEqual(pub.run(self.api, args('publications')), 0)
        self.assertEqual(json.loads(self.out.getvalue())[0]['token']['state'], 'expired')
        self.api.command.assert_not_called()
    def test_menu_cancel_has_no_mutation(self):
        with mock.patch.object(sys.stdin, 'isatty', return_value=True), mock.patch('builtins.input', return_value=''):
            self.assertEqual(pub.menu(self.api, args('manage-subscriptions')), 0)
        self.api.request.assert_not_called(); self.api.command.assert_not_called()


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.api = vp_api.Api('http://127.0.0.1:18080')
        self.api.cookie = 'vp_session=' + '1' * 64; self.api.csrf = '2' * 64
    def response(self, result, status=200, headers=None):
        response = mock.Mock(status=status)
        response.read.return_value = json.dumps({'schemaVersion': 1, 'requestId': 'test_request', 'operationId': None,
                                                 'result': result, 'error': None}).encode()
        values = {'Content-Type': 'application/json', 'Cache-Control': 'no-store',
                  'Pragma': 'no-cache', 'Referrer-Policy': 'no-referrer', **(headers or {})}
        response.getheader.side_effect = lambda key, default=None: values.get(key, default)
        return response
    def test_sensitive_transport_exact_cas_stable_key_and_no_retry(self):
        connection = mock.Mock(); connection.getresponse.return_value = self.response({'displayOnce': True})
        with mock.patch.object(vp_api.http.client, 'HTTPConnection', return_value=connection):
            self.api.command('/api/v1/publications/pub_test/token', 'publication_token_issue', 'stable_key', 5,
                             {'expiresInSeconds': 300, 'confirmIssueSecretUrl': True}, etag=True, sensitive=True)
        call = connection.request.call_args
        self.assertEqual(call.args[0:2], ('POST', '/api/v1/publications/pub_test/token'))
        body = json.loads(call.args[2]); headers = call.args[3]
        self.assertEqual(body['idempotencyKey'], 'stable_key'); self.assertEqual(body['expectedRevision'], 5)
        self.assertEqual(headers['If-Match'], '"5"'); self.assertEqual(headers['Origin'], self.api.origin)
        self.assertEqual(headers['Cookie'], self.api.cookie); self.assertEqual(headers['X-VP-CSRF'], self.api.csrf)
        connection.request.assert_called_once(); connection.close.assert_called_once()
    def test_sensitive_transport_failure_never_retries(self):
        connection = mock.Mock(); connection.getresponse.side_effect = OSError('synthetic transport failure')
        with mock.patch.object(vp_api.http.client, 'HTTPConnection', return_value=connection), self.assertRaises(InstallError):
            self.api.command('/api/v1/publications/pub_test/token', 'publication_token_issue', 'stable_key', 5,
                             {'expiresInSeconds': 300, 'confirmIssueSecretUrl': True}, etag=True, sensitive=True)
        connection.request.assert_called_once(); connection.close.assert_called_once()
    def test_missing_sensitive_headers_fails_closed(self):
        connection = mock.Mock(); connection.getresponse.return_value = self.response({}, headers={'Cache-Control': ''})
        with mock.patch.object(vp_api.http.client, 'HTTPConnection', return_value=connection), self.assertRaises(InstallError):
            self.api.request('POST', '/api/v1/publications/pub_test/token', {}, 1, sensitive=True)
        connection.request.assert_called_once()
    def test_sensitive_mode_cannot_target_export_or_unknown_route(self):
        for path in ('/api/v1/exports', '/api/v1/publications/pub_test/rotate', '/api/v1/credentials'):
            with mock.patch.object(vp_api.http.client, 'HTTPConnection') as connection, self.assertRaises(InstallError):
                self.api.request('POST', path, {}, sensitive=True)
            connection.assert_not_called()
    def test_ordinary_transport_refuses_sensitive_response(self):
        connection = mock.Mock(); connection.getresponse.return_value = self.response({'subscriptionUrl': 'synthetic'})
        with mock.patch.object(vp_api.http.client, 'HTTPConnection', return_value=connection), self.assertRaises(InstallError):
            self.api.request('GET', '/api/v1/publications')
    def test_opaque_ids_reject_path_url_dot_and_query(self):
        for value in ('../x', 'x.y', 'x?token=y', 'http://x', ''):
            with self.assertRaises(InstallError):
                pub.ident(value)


if __name__ == '__main__':
    unittest.main()

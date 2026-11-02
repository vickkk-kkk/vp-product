// Opt-in actual immutable daemon integration; NEVER a browser/cookie E2E claim.
// Synthetic credentials and exported URIs stay in memory. No values in failures.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';

const originValue = String.fromEnvironment('VP_PUBLICATION_ORIGIN');
const listenerPort = int.fromEnvironment('VP_PUBLICATION_LISTENER_PORT');
const codecPath = String.fromEnvironment('VP_PUBLICATION_CODEC');
const privateRoot = String.fromEnvironment('VP_PUBLICATION_PRIVATE_ROOT');
// Deliberately public synthetic fixture, never deployment/bootstrap default.
const fixtureToken =
    'dart-publication-synthetic-only-not-production-0123456789';
void require(bool condition, String checkpoint) {
  if (!condition) throw TestFailure(checkpoint);
}

MutationIdentity identity(String key, int revision) => MutationIdentity(
  requestId: 'dart_$key',
  idempotencyKey: 'dart_$key',
  expectedRevision: '$revision',
);

class ActualLoopbackTransport extends http.BaseClient {
  ActualLoopbackTransport(this.origin);
  final Uri origin;
  final http.Client inner = IOClient(HttpClient()..findProxy = (_) => 'DIRECT');
  String? cookie;
  String? dropNextMethod;
  final secrets = <String>{fixtureToken};
  final methods = <String>[];
  int requests = 0;
  int injectedDrops = 0;
  void rememberUrl(String value) {
    secrets.add(value);
    secrets.add(Uri.parse(value).pathSegments.last);
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    require(
      request.url.origin == origin.origin &&
          origin.host == '127.0.0.1' &&
          origin.scheme == 'http' &&
          request.url.path.startsWith('/api/v1/'),
      'transport_exact_loopback',
    );
    requests++;
    String? method;
    if (request is http.Request && request.body.isNotEmpty) {
      final value = jsonDecode(request.body) as Map<String, dynamic>;
      method = value['method'] as String?;
      if (method != null) methods.add(method);
    }
    if (request.method != 'GET') request.headers['Origin'] = origin.origin;
    if (cookie != null) request.headers['Cookie'] = cookie!;
    final response = await inner.send(request);
    final bytes = await response.stream.toBytes();
    require(bytes.length <= 1024 * 1024, 'metadata_body_limit');
    require(
      response.headers['cache-control'] == 'no-store',
      'metadata_no_store',
    );
    final cookieHeader = response.headers['set-cookie'];
    if (cookieHeader != null) {
      final value = Cookie.fromSetCookieValue(cookieHeader);
      require(
        value.name == 'vp_session' &&
            value.httpOnly &&
            value.secure &&
            cookieHeader.toLowerCase().contains('samesite=strict'),
        'cookie_flags_not_browser_semantics',
      );
      cookie = value.maxAge == 0 ? null : '${value.name}=${value.value}';
      if (cookie != null) {
        secrets.add(cookie!);
        secrets.add(value.value);
      }
    }
    final body = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    final result = body['result'];
    if (result is Map && result['csrfToken'] is String)
      secrets.add(result['csrfToken'] as String);
    if (result is Map && result['subscriptionUrl'] is String)
      rememberUrl(result['subscriptionUrl'] as String);
    if (method == dropNextMethod && method != null) {
      dropNextMethod = null;
      injectedDrops++;
      // REAL response is fully received after durable mutation, then deliberately
      // hidden from consumer. This is test fault injection, not network loss proof.
      throw TimeoutException('injected-after-real-response');
    }
    return http.StreamedResponse(
      Stream.value(bytes),
      response.statusCode,
      headers: response.headers,
      contentLength: bytes.length,
      request: request,
    );
  }

  @override
  void close() {
    cookie = null;
    inner.close();
  }
}

Future<ProductFailure> expectFailure(
  Future<Object?> Function() action, {
  String? code,
  bool unknown = false,
}) async {
  try {
    await action();
  } on ProductFailure catch (failure) {
    require(code == null || failure.code == code, 'failure_code');
    require(
      !unknown || failure.outcomeUnknown,
      'failure_must_remain_uncertain',
    );
    return failure;
  }
  throw TestFailure('expected_product_failure');
}

Future<OperationView> apply(
  HttpManagementApi api,
  ChangePlan plan,
  String key,
) async {
  final command = identity(key, int.parse(plan.baseRevision));
  var operation = await api.applyPlan(plan, plan.confirmationPhrase, command);
  final repeated = await api.applyPlan(plan, plan.confirmationPhrase, command);
  require(repeated.id == operation.id, 'apply_same_key_single_operation');
  final reconciled = await api.reconcile(command.idempotencyKey);
  require(reconciled?.id == operation.id, 'apply_safe_reconcile');
  final deadline = DateTime.now().add(const Duration(seconds: 45));
  while (!operation.terminal && DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 80));
    operation = await api.operation(operation.id);
  }
  require(
    operation.terminal && operation.status == '操作成功',
    'actual_apply_terminal_success',
  );
  return operation;
}

Future<String?> fetch(
  ActualLoopbackTransport fixture,
  String url,
  int expected, {
  int? revision,
}) async {
  final uri = Uri.parse(url);
  require(
    uri.origin == fixture.origin.origin &&
        uri.path.startsWith('/subscriptions/v1/') &&
        uri.query.isEmpty &&
        uri.fragment.isEmpty,
    'fetch_exact_owned_loopback',
  );
  // Separate client has no management cookie, Origin, CSRF or proxy.
  final client = IOClient(HttpClient()..findProxy = (_) => 'DIRECT');
  try {
    final request = http.Request('GET', uri)..followRedirects = false;
    final response = await client.send(request);
    final bytes = await response.stream.toBytes();
    require(
      response.statusCode == expected && bytes.length <= 256 * 1024,
      'subscription_status_and_bound',
    );
    require(
      response.headers['cache-control'] == 'no-store' &&
          response.headers['referrer-policy'] == 'no-referrer',
      'subscription_headers',
    );
    if (expected != 200) return null;
    require(
      response.headers['x-vp-config-revision'] == '$revision',
      'source_revision_header',
    );
    final body = utf8.decode(bytes);
    fixture.secrets.add(body);
    final lines = const LineSplitter().convert(body);
    require(lines.length == 1, 'single_exported_node');
    final node = Uri.parse(lines.single);
    require(
      node.scheme == 'vless' &&
          node.host == '127.0.0.1' &&
          node.port == listenerPort &&
          node.userInfo.isNotEmpty,
      'explicit_exported_endpoint',
    );
    fixture.secrets.add(lines.single);
    fixture.secrets.add(node.userInfo);
    final checker = await Process.start(codecPath, const []);
    final out = checker.stdout.fold<List<int>>(
      [],
      (out, part) => out..addAll(part),
    );
    final err = checker.stderr.fold<List<int>>(
      [],
      (out, part) => out..addAll(part),
    );
    checker.stdin.add(bytes);
    await checker.stdin.close();
    final code = await checker.exitCode.timeout(
      const Duration(seconds: 10),
      onTimeout: () {
        checker.kill(ProcessSignal.sigkill);
        throw TestFailure('codec_deadline');
      },
    );
    final stdout = await out, stderr = await err;
    require(
      code == 0 && stdout.length <= 8192 && stderr.isEmpty,
      'actual_rust_codec_exit',
    );
    final receipt = jsonDecode(utf8.decode(stdout)) as Map<String, dynamic>;
    require(
      receipt.length == 2 &&
          receipt['valid'] == true &&
          receipt['entries'] == 1,
      'actual_rust_codec_safe_receipt',
    );
    return node.userInfo;
  } finally {
    client.close();
  }
}

Future<void> forwardCachedCredential(String uuid) async {
  final hex = uuid.replaceAll('-', '');
  require(RegExp(r'^[0-9a-f]{32}$').hasMatch(hex), 'uuid_shape');
  final auth = [
    for (var i = 0; i < 32; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ];
  final target = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final marker = List<int>.generate(32, (i) => i + 11);
  final echo = () async {
    final socket = await target.first.timeout(const Duration(seconds: 5));
    final received = <int>[];
    try {
      await for (final part in socket.timeout(const Duration(seconds: 5))) {
        received.addAll(part);
        if (received.length >= marker.length) {
          socket.add(received);
          await socket.flush();
          break;
        }
      }
      require(received.length == marker.length, 'owned_target_received');
    } finally {
      socket.destroy();
    }
  }();
  final client = await Socket.connect(
    '127.0.0.1',
    listenerPort,
    timeout: const Duration(seconds: 5),
  );
  try {
    final port = target.port;
    client.add([
      0,
      ...auth,
      0,
      1,
      port >> 8,
      port & 255,
      1,
      127,
      0,
      0,
      1,
      ...marker,
    ]);
    await client.flush();
    final response = <int>[];
    await for (final part in client.timeout(const Duration(seconds: 5))) {
      response.addAll(part);
      if (response.length >= marker.length + 2) break;
    }
    require(
      response.length == 34 &&
          response[0] == 0 &&
          response[1] == 0 &&
          List.generate(
            32,
            (i) => response[i + 2] == marker[i],
          ).every((v) => v),
      'actual_cached_credential_forward',
    );
    await echo;
  } finally {
    client.destroy();
    await target.close();
  }
}

Future<int> scanPrivateState(Set<String> secrets) async {
  var files = 0;
  await for (final item in Directory(
    privateRoot,
  ).list(recursive: true, followLinks: false)) {
    require(item is! Link, 'private_state_symlink');
    if (item is! File) continue;
    require(
      await item.length() <= 128 * 1024 * 1024,
      'private_state_scan_bound',
    );
    final bytes = await item.readAsBytes();
    final content = latin1.decode(bytes);
    for (final secret in secrets) {
      require(
        !content.contains(latin1.decode(utf8.encode(secret))),
        'plaintext_secret_in_private_state',
      );
    }
    files++;
  }
  return files;
}

void main() {
  test(
    'actual immutable daemon typed UUID publication and recovery journey',
    () async {
      var stage = 'initialize';
      final fixture = ActualLoopbackTransport(Uri.parse(originValue));
      final api = HttpManagementApi(client: fixture, origin: fixture.origin);
      final checks = <String>[];
      var codecChecks = 0;
      try {
        stage = 'authentication';
        await expectFailure(api.restoreSession, code: 'AUTH_REQUIRED');
        await api.login('synthetic-subscription-admin', fixtureToken);
        await api.restoreSession();
        var workspace = await api.readPublicationWorkspace();
        require(
          workspace.activeRevision == 0 &&
              workspace.credentials.isEmpty &&
              workspace.supportsUuid &&
              workspace.presets.every(
                (p) => p.capability.status != CapabilityStatus.certified,
              ),
          'initial_actual_capabilities',
        );
        checks.add('actual_auth_uuid_capability_not_protocol_certification');
        stage = 'credential_unknown';
        final creation = identity('credential', 0);
        fixture.dropNextMethod = 'credential_create';
        await expectFailure(
          () => api.generateUuidCredential(creation),
          unknown: true,
        );
        require(
          fixture.methods.where((m) => m == 'credential_create').length == 1,
          'credential_no_auto_retry',
        );
        final credential = await api.generateUuidCredential(creation);
        require(
          (await api.credentialInventory()).credentials.length == 1,
          'credential_same_key_one_vault_object',
        );
        checks.add(
          'real_credential_postreceipt_drop_explicit_same_key_recovery',
        );
        stage = 'new_node_typed_plan';
        final plan = await api.prepareNewUuidListener(
          NewUuidListenerInput(
            listenerId: 'dart_listener',
            userId: 'dart_user',
            name: 'Temporary Dart loopback node',
            bindAddress: '127.0.0.1',
            port: listenerPort,
          ),
          credential,
          identity('new_node', 0),
        );
        stage = 'first_apply';
        await apply(api, plan, 'first_apply');
        stage = 'first_workspace';
        workspace = await api.readPublicationWorkspace();
        require(
          workspace.activeRevision == 1 &&
              workspace.observedRevision == 1 &&
              workspace.sources.single.selectable,
          'fresh_actual_source_required',
        );
        checks.add(
          'typed_uuid_draft_validate_plan_apply_reconcile_fresh_observation',
        );
        stage = 'publication_create';
        final source = workspace.sources.single;
        final draft = PublicationDraft(
          name: 'Temporary Dart publication',
          enabled: true,
          sources: [
            PublicationSourceMapping(
              listenerId: source.listenerId,
              userId: source.userId,
              host: '127.0.0.1',
              port: listenerPort,
              security: const PublicationSecurityNone(),
            ),
          ],
        );
        var publication = await api.createPublication(
          draft,
          identity('publication', 1),
        );
        require(
          publication.sourceRevision == 1 &&
              publication.token.state == PublicationTokenState.notIssued,
          'publication_pinned_unissued',
        );
        stage = 'issue_and_fetch';
        final issue = identity('first_issue', publication.revision);
        final handoff = await api.issuePublicationToken(
          publication.id,
          600,
          issue,
        );
        final firstUrl = handoff.takeOnce();
        require(
          firstUrl != null &&
              handoff.takeOnce() == null &&
              handoff.developmentLoopback,
          'one_time_display_handoff',
        );
        final cachedCredential = await fetch(
          fixture,
          firstUrl!,
          200,
          revision: 1,
        );
        codecChecks++;
        require(cachedCredential != null, 'codec_credential');
        await forwardCachedCredential(cachedCredential!);
        // Explicit negative conformance request, not the production retry path.
        await expectFailure(
          () => api.issuePublicationToken(publication.id, 600, issue),
          code: 'SECRET_RESULT_UNAVAILABLE',
          unknown: true,
        );
        publication = await api.getPublication(publication.id);
        require(publication.token.version == 1, 'same_key_does_not_mint');
        checks.add(
          'one_time_url_independent_fetch_real_rust_codec_actual_forward_no_secret_replay',
        );
        stage = 'lost_token_result';
        fixture.dropNextMethod = 'publication_token_issue';
        final beforeIssues = fixture.methods
            .where((m) => m == 'publication_token_issue')
            .length;
        await expectFailure(
          () => api.issuePublicationToken(
            publication.id,
            600,
            identity('lost_issue', publication.revision),
          ),
          unknown: true,
        );
        require(
          fixture.methods.where((m) => m == 'publication_token_issue').length ==
              beforeIssues + 1,
          'no_automatic_new_key_issue',
        );
        publication = await api.getPublication(publication.id);
        require(
          publication.token.version == 2,
          'metadata_confirms_unavailable_issued_result',
        );
        await fetch(fixture, firstUrl, 401);
        final replacement = await api.issuePublicationToken(
          publication.id,
          600,
          identity('explicit_replacement', publication.revision),
        );
        final replacementUrl = replacement.takeOnce()!;
        publication = replacement.publication;
        require(
          publication.token.version == 3,
          'explicit_rotation_new_version',
        );
        require(
          await fetch(fixture, replacementUrl, 200, revision: 1) ==
              cachedCredential,
          'rotation_not_node_revocation',
        );
        codecChecks++;
        checks.add(
          'real_token_postreceipt_drop_safe_metadata_explicit_new_key_rotation',
        );
        stage = 'revoke';
        publication = await api.revokePublicationToken(
          publication.id,
          identity('revoke', publication.revision),
        );
        require(
          publication.token.state == PublicationTokenState.revoked,
          'revoke_metadata',
        );
        await fetch(fixture, replacementUrl, 401);
        await forwardCachedCredential(cachedCredential);
        checks.add('actual_revoke_blocks_fetch_cached_node_still_forwards');
        stage = 'stale_republish';
        final again = await api.issuePublicationToken(
          publication.id,
          600,
          identity('explicit_resume', publication.revision),
        );
        final currentUrl = again.takeOnce()!;
        publication = again.publication;
        final edit = await api.planListener(
          ListenerDraft(
            listenerId: source.listenerId,
            name: 'Explicit renamed node',
            presetKey: '',
            bind: '127.0.0.1',
            port: listenerPort,
            enabled: true,
          ),
          identity('rename', 1),
        );
        await apply(api, edit, 'second_apply');
        workspace = await api.readPublicationWorkspace();
        require(
          workspace.activeRevision == 2 && workspace.observedRevision == 2,
          'second_actual_revision',
        );
        await fetch(fixture, currentUrl, 412);
        publication = await api.replacePublication(
          publication.id,
          draft,
          2,
          identity('republish', publication.revision),
        );
        require(
          publication.sourceRevision == 2,
          'explicit_republish_source_revision',
        );
        require(
          await fetch(fixture, currentUrl, 200, revision: 2) ==
              cachedCredential,
          'republish_preserves_unchanged_credential',
        );
        codecChecks++;
        checks.add('actual_config_change_stale_denial_explicit_republish');
        stage = 'logout_scan';
        await api.logout();
        require(
          !api.authenticated && fixture.cookie == null,
          'logout_authority_cleared',
        );
        final files = await scanPrivateState(fixture.secrets);
        require(
          files > 0 && fixture.injectedDrops == 2,
          'scan_and_fault_injection_count',
        );
        checks.add('session_logout_private_file_plaintext_scan');
        // Only fixed authored checkpoint names and integer counts leave the test.
        // ignore: avoid_print
        print(
          'VP_DART_PUBLICATION_RECEIPT ${jsonEncode({'status': 'passed', 'checks': checks, 'httpRequests': fixture.requests, 'codecChecks': codecChecks, 'actualForwardChecks': 2, 'postReceiptFaultInjections': fixture.injectedDrops, 'privateFilesScanned': files})}',
        );
      } catch (error) {
        final detail = error is ProductFailure
            ? const {
                    'CONFIG_INVALID',
                    'CONFIG_UNSUPPORTED',
                    'VALIDATION_FAILED',
                    'DRAFT_CHANGED',
                    'CONTRACT_INCOMPATIBLE',
                    'REVISION_CONFLICT',
                    'CORE_UNAVAILABLE',
                    'MANAGEMENT_TRANSPORT_FAILED',
                  }.contains(error.code)
                  ? error.code
                  : 'product_failure'
            : error is TestFailure &&
                  RegExp(r'^[a-z_]+$').hasMatch(error.message ?? '')
            ? error.message
            : 'external_failure';
        // ignore: avoid_print
        print('VP_DART_SAFE_FAILURE $detail');
        // Never stringify external exception, request, response or URI-bearing object.
        throw TestFailure('actual_publication_checkpoint_$stage');
      } finally {
        api.close();
      }
    },
    skip: originValue.isEmpty
        ? 'Requires explicit private immutable daemon fixture.'
        : false,
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

import 'dart:async';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';

http.Response envelope(
  Object? result, {
  int status = 200,
  String requestId = 'response_1',
}) => http.Response(
  jsonEncode({
    'schemaVersion': 1,
    'requestId': requestId,
    'operationId': null,
    'result': result,
  }),
  status,
  headers: {'content-type': 'application/json'},
);
http.Response rejection(
  String code,
  String stage, {
  int status = 400,
  String requestId = 'request_1',
}) => http.Response(
  jsonEncode({
    'schemaVersion': 1,
    'requestId': requestId,
    'operationId': null,
    'error': {
      'code': code,
      'messageKey': 'error.action_failed',
      'safeArgs': <String, Object?>{},
      'fieldPath': null,
      'retryable': false,
      'stage': stage,
      'capabilityKey': null,
      'remediation': null,
      'diagnosticId': null,
    },
  }),
  status,
  headers: {'content-type': 'application/json'},
);
Map<String, Object?> operation() => {
  'id': 'operation_1',
  'planId': null,
  'status': 'queued',
  'stage': 'validate',
  'cancellable': true,
  'completedSteps': 0,
  'totalSteps': 8,
  'baseRevision': 0,
  'targetRevision': 1,
  'error': null,
};
const identity = MutationIdentity(
  requestId: 'request_1',
  idempotencyKey: 'key_1',
  expectedRevision: '0',
);
ChangePlan plan() => ChangePlan(
  id: 'plan_1',
  hash: 'a' * 64,
  baseRevision: '0',
  target: 'Test only',
  changes: const [],
  impacts: const [],
  recovery: 'Test only',
  expiresAt: DateTime.now().add(const Duration(minutes: 1)),
  confirmationPhrase: 'apply',
);
void main() {
  test('late session restoration cannot reauthenticate after logout', () async {
    final pending = Completer<http.Response>();
    var restores = 0;
    final api = HttpManagementApi(
      client: MockClient((request) async {
        if (request.url.path.endsWith('/auth/session')) {
          restores++;
          return restores == 1
              ? envelope({'csrfToken': 'initial_test_token'})
              : pending.future;
        }
        return envelope(null);
      }),
      origin: Uri.parse('https://example.invalid'),
    );
    addTearDown(api.close);
    await api.restoreSession();
    final restoring = api.restoreSession();
    await api.logout();
    pending.complete(envelope({'csrfToken': 'late_test_token'}));
    await expectLater(restoring, throwsA(isA<ProductFailure>()));
    expect(api.authenticated, isFalse);
  });
  test('unknown mandatory wire feature stays incompatible', () async {
    final api = HttpManagementApi(
      client: MockClient(
        (request) async => switch (request.url.path) {
          '/api/v1/auth/session' => envelope({'csrfToken': 'test_token'}),
          '/api/v1/build' => envelope({
            'schemaVersion': 1,
            'requiredFeatures': ['future.required-wire-feature'],
            'development': true,
          }),
          _ => envelope(null),
        },
      ),
      origin: Uri.parse('https://example.invalid'),
    );
    addTearDown(api.close);
    await expectLater(
      api.snapshot(),
      throwsA(
        isA<ProductFailure>().having(
          (error) => error.code,
          'code',
          'CONTRACT_INCOMPATIBLE',
        ),
      ),
    );
  });

  test('non-loopback plaintext origin is rejected before requests', () {
    expect(
      () => HttpManagementApi(
        client: MockClient((_) async => envelope(null)),
        origin: Uri.parse('http://example.invalid'),
      ),
      throwsArgumentError,
    );
  });
  test(
    'session restoration and mutations stay same origin and attach CSRF, never token query',
    () async {
      final requests = <http.Request>[];
      final api = HttpManagementApi(
        client: MockClient((request) async {
          requests.add(request);
          if (request.url.path.endsWith('/auth/session'))
            return envelope({'csrfToken': 'csrf_test_only'});
          return envelope(operation(), requestId: 'request_1');
        }),
        origin: Uri.parse('https://management.example.invalid/app/'),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await api.cancelOperation('operation_1', identity);
      expect(requests.last.url.origin, 'https://management.example.invalid');
      expect(requests.last.url.query, isEmpty);
      expect(requests.last.headers['X-VP-CSRF'], 'csrf_test_only');
      expect(requests.last.followRedirects, isFalse);
      final body = jsonDecode(requests.last.body) as Map<String, dynamic>;
      expect(body['idempotencyKey'], 'key_1');
      expect(body['expectedRevision'], 0);
    },
  );
  test('missing session prevents mutation before sending', () async {
    var sends = 0;
    final api = HttpManagementApi(
      client: MockClient((_) async {
        sends++;
        return envelope(null);
      }),
      origin: Uri.parse('https://example.invalid'),
    );
    addTearDown(api.close);
    await expectLater(
      api.applyPlan(plan(), 'apply', identity),
      throwsA(
        isA<ProductFailure>().having(
          (e) => e.definitelyNotApplied,
          'definite local rejection',
          isTrue,
        ),
      ),
    );
    expect(sends, 0);
  });
  test(
    'transport timeout after apply is unknown, never automatically retried',
    () async {
      var applies = 0;
      final api = HttpManagementApi(
        client: MockClient((request) async {
          if (request.url.path.endsWith('/auth/session'))
            return envelope({'csrfToken': 'csrf_test'});
          applies++;
          throw TimeoutException('secret URL must not escape');
        }),
        origin: Uri.parse('https://example.invalid'),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.applyPlan(plan(), 'apply', identity),
        throwsA(
          isA<ProductFailure>()
              .having((e) => e.outcomeUnknown, 'outcome', isTrue)
              .having(
                (e) => e.message,
                'redacted',
                isNot(contains('secret URL')),
              ),
        ),
      );
      expect(applies, 1);
    },
  );
  test(
    'mismatched response requestId is not accepted as a mutation receipt',
    () async {
      final api = HttpManagementApi(
        client: MockClient(
          (request) async => request.url.path.endsWith('/auth/session')
              ? envelope({'csrfToken': 'csrf_test'})
              : envelope(operation(), requestId: 'another_request'),
        ),
        origin: Uri.parse('https://example.invalid'),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.cancelOperation('operation_1', identity),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.outcomeUnknown,
            'unknown',
            isTrue,
          ),
        ),
      );
    },
  );
  test(
    'valid structured pre-application rejection is definitely not applied',
    () async {
      final api = HttpManagementApi(
        client: MockClient(
          (request) async => request.url.path.endsWith('/auth/session')
              ? envelope({'csrfToken': 'csrf_test'})
              : rejection('REVISION_CONFLICT', 'validate', status: 409),
        ),
        origin: Uri.parse('https://example.invalid'),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.applyPlan(plan(), 'apply', identity),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.definitelyNotApplied,
            'known rejection',
            isTrue,
          ),
        ),
      );
    },
  );
  test('session expiration clears in-memory mutation authority', () async {
    var first = true;
    final api = HttpManagementApi(
      client: MockClient((_) async {
        if (first) {
          first = false;
          return envelope({'csrfToken': 'csrf_test'});
        }
        return rejection('AUTH_REQUIRED', 'authenticate', status: 401);
      }),
      origin: Uri.parse('https://example.invalid'),
    );
    addTearDown(api.close);
    await api.restoreSession();
    await expectLater(
      api.operation('operation_1'),
      throwsA(isA<ProductFailure>()),
    );
    expect(api.authenticated, isFalse);
  });
  test(
    'empty config does not fabricate listeners or observed revision',
    () async {
      final api = HttpManagementApi(
        client: MockClient(
          (request) async => switch (request.url.path) {
            '/api/v1/auth/session' => envelope({'csrfToken': 'csrf_test'}),
            '/api/v1/build' => envelope({
              'schemaVersion': 1,
              'requiredFeatures': <Object?>[],
              'development': true,
              'release': {
                'api': {'major': 1},
                'releaseId': 'test_release',
              },
            }),
            '/api/v1/capabilities' => envelope(<Object?>[]),
            '/api/v1/config' => envelope({'revision': 0, 'config': null}),
            '/api/v1/snapshot' => envelope({
              'schemaVersion': 1,
              'desiredRevision': 0,
              'observedRevision': null,
              'listeners': <Object?>[],
              'operations': <Object?>[],
            }),
            _ => throw StateError('unexpected route'),
          },
        ),
        origin: Uri.parse('https://example.invalid'),
      );
      addTearDown(api.close);
      final snapshot = await api.snapshot();
      expect(snapshot.listeners, isEmpty);
      expect(snapshot.observedRevision, isNull);
    },
  );
  test(
    'different revision between active config and snapshot is rejected',
    () async {
      final api = HttpManagementApi(
        client: MockClient(
          (request) async => switch (request.url.path) {
            '/api/v1/auth/session' => envelope({'csrfToken': 'csrf_test'}),
            '/api/v1/build' => envelope({
              'schemaVersion': 1,
              'requiredFeatures': <Object?>[],
              'development': true,
              'release': {
                'api': {'major': 1},
              },
            }),
            '/api/v1/capabilities' => envelope(<Object?>[]),
            '/api/v1/config' => envelope({'revision': 2, 'config': null}),
            '/api/v1/snapshot' => envelope({
              'schemaVersion': 1,
              'desiredRevision': 1,
              'observedRevision': null,
              'listeners': <Object?>[],
              'operations': <Object?>[],
            }),
            _ => throw StateError('unexpected route'),
          },
        ),
        origin: Uri.parse('https://example.invalid'),
      );
      addTearDown(api.close);
      await expectLater(
        api.snapshot(),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.code,
            'code',
            'REVISION_CONFLICT',
          ),
        ),
      );
    },
  );
  test('oversized response is rejected', () async {
    final api = HttpManagementApi(
      client: MockClient((_) async => envelope({'csrfToken': 'x' * 500})),
      origin: Uri.parse('https://example.invalid'),
      maxResponseBytes: 100,
    );
    addTearDown(api.close);
    await expectLater(api.restoreSession(), throwsA(isA<ProductFailure>()));
  });
}

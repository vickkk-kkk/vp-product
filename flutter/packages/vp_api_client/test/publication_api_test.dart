// Isolated HTTP fixtures, not live integration or deployed credentials.
import 'dart:async';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'http_management_api_test.dart' show envelope, rejection;

const cmd = MutationIdentity(
  requestId: 'publication_request',
  idempotencyKey: 'publication_key',
  expectedRevision: '4',
);
Map<String, Object?> credentialJson() => {
  'schemaVersion': 1,
  'id': 'credential_fixture',
  'revision': 1,
  'kind': {'kind': 'uuid'},
  'secretRef': 'secret:fixture_uuid',
  'state': 'available',
  'createdAt': 1000,
  'displayKey': 'credential.managed',
};
Map<String, Object?> sourceJson() => {
  'listenerId': 'listener_fixture',
  'userId': 'user_fixture',
  'endpoint': {'host': '127.0.0.1', 'port': 18090},
  'clientSecurity': {'kind': 'none'},
};
Map<String, Object?> publicationJson({bool active = false}) => {
  'schemaVersion': 1,
  'id': 'publication_fixture',
  'revision': active ? 5 : 4,
  'name': 'Test publication',
  'sourceRevision': 2,
  'enabled': true,
  'format': 'uri_list',
  'sources': [sourceJson()],
  'token': {
    'state': active ? 'active' : 'not_issued',
    'version': active ? 1 : 0,
    'issuedAt': active ? 1000 : null,
    'expiresAt': active ? 301000 : null,
  },
  'createdAt': 1000,
  'updatedAt': 1000,
  'lastSuccessfulReadAt': null,
};
Map<String, Object?> issueJson() => {
  'publication': publicationJson(active: true),
  'displayOnce': true,
  'subscriptionUrl':
      'http://127.0.0.1:18080/subscriptions/v1/publication_fixture/vps1_${'a' * 64}',
};
http.Response sensitiveEnvelope(
  Object? value, {
  String requestId = 'publication_request',
}) {
  final response = envelope(value, requestId: requestId);
  return http.Response(
    response.body,
    response.statusCode,
    headers: {
      ...response.headers,
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
    },
  );
}

HttpManagementApi apiFor(Future<http.Response> Function(http.Request) handle) =>
    HttpManagementApi(
      client: MockClient(
        (request) async => request.url.path == '/api/v1/auth/session'
            ? envelope({'csrfToken': 'synthetic_csrf'})
            : handle(request),
      ),
      origin: Uri.parse('http://127.0.0.1:18080'),
    );
PublicationDraft draft() => PublicationDraft(
  name: 'Explicit source',
  enabled: true,
  sources: [
    const PublicationSourceMapping(
      listenerId: 'listener_fixture',
      userId: 'user_fixture',
      host: '127.0.0.1',
      port: 18090,
      security: PublicationSecurityNone(),
    ),
  ],
);

void main() {
  test(
    'credential generation sends explicit UUID and safe metadata only',
    () async {
      final requests = <http.Request>[];
      final api = apiFor((request) async {
        requests.add(request);
        return envelope(credentialJson(), requestId: cmd.requestId);
      });
      addTearDown(api.close);
      await api.restoreSession();
      final value = await api.generateUuidCredential(cmd);
      final body = jsonDecode(requests.single.body) as Map<String, dynamic>;
      expect(body['method'], 'credential_create');
      expect(body['payload'], {
        'kind': {'kind': 'uuid'},
        'confirmGenerate': true,
      });
      expect(body['idempotencyKey'], cmd.idempotencyKey);
      expect(value.kind.isUuid, isTrue);
      expect(value.secretRef, 'secret:fixture_uuid');
      expect(value.state, ManagedCredentialState.available);
      expect(requests.single.headers['X-VP-CSRF'], 'synthetic_csrf');
    },
  );
  test(
    'publication create and replace preserve explicit endpoint/security and CAS',
    () async {
      final requests = <http.Request>[];
      final api = apiFor((request) async {
        requests.add(request);
        return envelope(publicationJson(), requestId: cmd.requestId);
      });
      addTearDown(api.close);
      await api.restoreSession();
      await api.createPublication(draft(), cmd);
      await api.replacePublication('publication_fixture', draft(), 2, cmd);
      final create = jsonDecode(requests[0].body) as Map<String, dynamic>;
      final replace = jsonDecode(requests[1].body) as Map<String, dynamic>;
      expect(create['payload']['sources'], [sourceJson()]);
      expect(create['payload']['confirmPublishConnectionSecrets'], true);
      expect(create['payload']['format'], 'uri_list');
      expect(requests[1].method, 'PUT');
      expect(requests[1].headers['If-Match'], '"4"');
      expect(replace['payload']['sourceRevision'], 2);
    },
  );
  test(
    'issued URL is one-shot, redacted, no automatic fetch or clipboard',
    () async {
      var requests = 0;
      final api = apiFor((request) async {
        requests++;
        expect(
          request.url.path,
          '/api/v1/publications/publication_fixture/token',
        );
        return sensitiveEnvelope(issueJson());
      });
      addTearDown(api.close);
      await api.restoreSession();
      final result = await api.issuePublicationToken(
        'publication_fixture',
        300,
        cmd,
      );
      expect(result.toString(), 'OneTimePublicationSecret([REDACTED])');
      expect(
        () => jsonEncode(result),
        throwsA(isA<JsonUnsupportedObjectError>()),
      );
      expect(result.developmentLoopback, isTrue);
      expect(result.publication.id, 'publication_fixture');
      expect(result.takeOnce(), isNotNull);
      expect(result.takeOnce(), isNull);
      expect(result.isAvailable, isFalse);
      expect(requests, 1);
    },
  );
  test(
    'same-key unavailable is unknown and never automatically issues again',
    () async {
      var requests = 0;
      final api = apiFor((request) async {
        requests++;
        final r = rejection(
          'SECRET_RESULT_UNAVAILABLE',
          'export',
          status: 409,
          requestId: cmd.requestId,
        );
        return http.Response(
          r.body,
          r.statusCode,
          headers: {
            ...r.headers,
            'cache-control': 'no-store',
            'referrer-policy': 'no-referrer',
          },
        );
      });
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.issuePublicationToken('publication_fixture', 300, cmd),
        throwsA(
          isA<ProductFailure>()
              .having((e) => e.code, 'code', 'SECRET_RESULT_UNAVAILABLE')
              .having((e) => e.outcomeUnknown, 'unknown', isTrue)
              .having((e) => e.message, 'safe explanation', contains('可能已签发')),
        ),
      );
      expect(requests, 1);
    },
  );
  test(
    'late issue after logout is discarded and callback carries no secret',
    () async {
      final pending = Completer<http.Response>();
      final api = apiFor(
        (request) async => request.url.path.endsWith('/token')
            ? pending.future
            : envelope(null),
      );
      addTearDown(api.close);
      await api.restoreSession();
      var changes = 0;
      void listener() {
        changes++;
      }

      api.addSessionListener(listener);
      final issue = api.issuePublicationToken('publication_fixture', 300, cmd);
      final rejected = expectLater(
        issue,
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.code,
            'code',
            'SESSION_CHANGED',
          ),
        ),
      );
      await api.logout();
      pending.complete(sensitiveEnvelope(issueJson()));
      await rejected;
      expect(changes, greaterThanOrEqualTo(1));
      expect(api.authenticated, isFalse);
      api.removeSessionListener(listener);
    },
  );
  test(
    'logout disposes previously returned unconsumed one-time result',
    () async {
      final api = apiFor(
        (request) async => request.url.path.endsWith('/token')
            ? sensitiveEnvelope(issueJson())
            : envelope(null),
      );
      addTearDown(api.close);
      await api.restoreSession();
      final result = await api.issuePublicationToken(
        'publication_fixture',
        300,
        cmd,
      );
      expect(result.isAvailable, isTrue);
      await api.logout();
      expect(result.takeOnce(), isNull);
    },
  );
  test(
    'rapid token calls are locked at adapter without a second request',
    () async {
      final pending = Completer<http.Response>();
      var requests = 0;
      final api = apiFor((request) async {
        requests++;
        return pending.future;
      });
      addTearDown(api.close);
      await api.restoreSession();
      final first = api.issuePublicationToken('publication_fixture', 300, cmd);
      await expectLater(
        api.issuePublicationToken('publication_fixture', 300, cmd),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.definitelyNotApplied,
            'not submitted',
            isTrue,
          ),
        ),
      );
      pending.complete(sensitiveEnvelope(issueJson()));
      (await first).dispose();
      expect(requests, 1);
    },
  );
  test(
    'missing no-store response and malformed URL fail without exposing bytes',
    () async {
      final api = apiFor(
        (request) async => envelope(issueJson(), requestId: cmd.requestId),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.issuePublicationToken('publication_fixture', 300, cmd),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.toString(),
            'redacted',
            'CONTRACT_INCOMPATIBLE',
          ),
        ),
      );
      final invalid = apiFor(
        (request) async => sensitiveEnvelope({
          ...issueJson(),
          'subscriptionUrl':
              'http://external.invalid/subscriptions/v1/publication_fixture/vps1_${'b' * 64}',
        }),
      );
      addTearDown(invalid.close);
      await invalid.restoreSession();
      await expectLater(
        invalid.issuePublicationToken('publication_fixture', 300, cmd),
        throwsA(isA<ProductFailure>()),
      );
    },
  );
  test(
    'safe metadata rejects unexpected secret field and unknown security',
    () async {
      var body = <String, Object?>{
        ...publicationJson(),
        'subscriptionUrl': 'forbidden_in_metadata',
      };
      final api = apiFor((request) async => envelope(body));
      addTearDown(api.close);
      await expectLater(
        api.getPublication('publication_fixture'),
        throwsA(isA<ProductFailure>()),
      );
      body = {
        ...publicationJson(),
        'sources': [
          {
            ...sourceJson(),
            'clientSecurity': {'kind': 'insecure'},
          },
        ],
      };
      await expectLater(
        api.getPublication('publication_fixture'),
        throwsA(isA<ProductFailure>()),
      );
    },
  );
  test(
    'DTO collections are deep immutable and security round trip is lossless',
    () async {
      final alpn = ['h2'];
      final pins = ['c' * 64];
      final security = PublicationSecurityTls(
        serverName: 'server.example.invalid',
        alpn: alpn,
        trust: PublicationSpkiTrust(pins),
        clientHelloFingerprint: 'chrome',
      );
      alpn.add('http/1.1');
      pins.add('d' * 64);
      expect(security.alpn, ['h2']);
      expect((security.trust as PublicationSpkiTrust).pins, hasLength(1));
      expect(() => security.alpn.add('mutate'), throwsUnsupportedError);
      final input = PublicationDraft(
        name: 'TLS explicit',
        enabled: true,
        sources: [
          PublicationSourceMapping(
            listenerId: 'listener_fixture',
            userId: 'user_fixture',
            host: 'server.example.invalid',
            port: 443,
            security: security,
          ),
        ],
      );
      final api = apiFor((request) async {
        final body = jsonDecode(request.body) as Map<String, dynamic>;
        final sources = body['payload']['sources'];
        return envelope({
          ...publicationJson(),
          'sources': sources,
        }, requestId: cmd.requestId);
      });
      addTearDown(api.close);
      await api.restoreSession();
      final result = await api.createPublication(input, cmd);
      final returned = result.sources.single.security as PublicationSecurityTls;
      expect(returned.serverName, 'server.example.invalid');
      expect(returned.clientHelloFingerprint, 'chrome');
      expect(returned.alpn, ['h2']);
      expect((returned.trust as PublicationSpkiTrust).pins, ['c' * 64]);
      expect(() => result.sources.clear(), throwsUnsupportedError);
    },
  );
  test(
    'workspace uses observed listener/user evidence, not desired config',
    () async {
      var ready = true;
      int? observedRevision = 2;
      final activeConfig = configJson();
      final api = apiFor(
        (request) async => switch (request.url.path) {
          '/api/v1/config' => envelope({'revision': 2, 'config': activeConfig}),
          '/api/v1/snapshot' => envelope(
            observationJson(ready: ready, revision: observedRevision),
          ),
          '/api/v1/credentials' => envelope({
            'schemaVersion': 1,
            'credentials': [credentialJson()],
            'supportedKinds': [
              {'kind': 'uuid'},
            ],
          }),
          '/api/v1/publications' => envelope([publicationJson()]),
          '/api/v1/build' => envelope({
            'schemaVersion': 1,
            'requiredFeatures': <String>[],
            'development': true,
            'release': {
              'api': {'major': 1},
            },
          }),
          '/api/v1/capabilities' => envelope(<Object?>[]),
          _ => throw StateError('unexpected path'),
        },
      );
      addTearDown(api.close);
      final initial = await api.readPublicationWorkspace();
      expect(initial.supportsUuid, isTrue);
      expect(initial.developmentBuild, isTrue);
      expect(initial.sources.single.selectable, isTrue);
      expect(initial.presets, isEmpty);
      ready = false;
      expect(
        (await api.readPublicationWorkspace()).sources.single.selectable,
        isFalse,
      );
      ready = true;
      observedRevision = null;
      expect(
        (await api.readPublicationWorkspace()).sources.single.selectable,
        isFalse,
      );
      observedRevision = 2;
      final listeners = activeConfig['listeners'] as List<Object?>;
      final listener = listeners.single as Map<String, Object?>;
      final protocol = listener['protocol'] as Map<String, Object?>;
      protocol['protocol'] = {'kind': 'vless', 'flow': 'xtls-rprx-vision'};
      final unsupported = await api.readPublicationWorkspace();
      expect(unsupported.sources.single.selectable, isFalse);
      expect(unsupported.sources.single.reason, contains('当前发布器暂不支持'));
      expect(() => initial.sources.clear(), throwsUnsupportedError);
    },
  );
  test(
    'new listener uses exact generated ref and deterministic plan identities',
    () async {
      final writes = <Map<String, Object?>>[];
      final api = apiFor((request) async {
        if (request.url.path == '/api/v1/credentials')
          return envelope({
            'schemaVersion': 1,
            'credentials': [credentialJson()],
            'supportedKinds': [
              {'kind': 'uuid'},
            ],
          });
        if (request.url.path == '/api/v1/config')
          return envelope({'revision': 4, 'config': configJson()});
        final body = jsonDecode(request.body) as Map<String, Object?>;
        writes.add(body);
        final method = body['method'];
        final id = body['requestId'] as String;
        if (method == 'draft_create')
          return envelope({
            'id': 'draft_fixture',
            'revision': 1,
            'baseRevision': 4,
            'config': body['payload'],
          }, requestId: id);
        if (method == 'validate')
          return envelope({'valid': true}, requestId: id);
        if (method == 'plan_create')
          return envelope({
            'id': 'plan_fixture',
            'planHash': 'e' * 64,
            'baseRevision': 4,
            'impact': 'restart',
            'requiredPermissions': <String>[],
            'recoveryAvailable': true,
            'recoveryDescriptionKey': 'recovery.previous',
            'expiresAt': DateTime.now()
                .add(const Duration(minutes: 1))
                .millisecondsSinceEpoch,
          }, requestId: id);
        throw StateError('unexpected write');
      });
      addTearDown(api.close);
      await api.restoreSession();
      final credential = (await api.credentialInventory()).credentials.single;
      const input = NewUuidListenerInput(
        listenerId: 'new_listener',
        userId: 'new_user',
        name: 'Explicit test listener',
        bindAddress: '127.0.0.1',
        port: 18091,
      );
      await api.prepareNewUuidListener(input, credential, cmd);
      await api.prepareNewUuidListener(input, credential, cmd);
      expect(writes.map((w) => w['idempotencyKey']).toList(), [
        'publication_key_draft',
        'publication_key_validate',
        'publication_key_plan',
        'publication_key_draft',
        'publication_key_validate',
        'publication_key_plan',
      ]);
      final config = writes.first['payload'] as Map<String, Object?>;
      final listeners = config['listeners'] as List<Object?>;
      expect(listeners.length, 2);
      final added = listeners.last as Map<String, Object?>;
      expect((added['protocol'] as Map<String, Object?>)['users'], [
        {
          'id': 'new_user',
          'credentialRef': 'secret:fixture_uuid',
          'enabled': true,
        },
      ]);
      expect(added['security'], {'kind': 'none'});
      expect(api.lastPreparedDraftId, 'draft_fixture');
    },
  );
  test('revision conflict before draft sends no mutation', () async {
    var writes = 0;
    final api = apiFor((request) async {
      if (request.method != 'GET') writes++;
      return request.url.path.endsWith('/credentials')
          ? envelope({
              'schemaVersion': 1,
              'credentials': [credentialJson()],
              'supportedKinds': [
                {'kind': 'uuid'},
              ],
            })
          : envelope({'revision': 5, 'config': configJson()});
    });
    addTearDown(api.close);
    await api.restoreSession();
    final credential = (await api.credentialInventory()).credentials.single;
    await expectLater(
      api.prepareNewUuidListener(
        const NewUuidListenerInput(
          listenerId: 'new_listener',
          userId: 'new_user',
          name: 'Test',
          bindAddress: '127.0.0.1',
          port: 18091,
        ),
        credential,
        cmd,
      ),
      throwsA(
        isA<ProductFailure>().having(
          (e) => e.definitelyNotApplied,
          'no write',
          isTrue,
        ),
      ),
    );
    expect(writes, 0);
  });

  test(
    'replayed draft with altered contents cannot proceed to validation',
    () async {
      var writes = 0;
      final api = apiFor((request) async {
        if (request.url.path == '/api/v1/credentials')
          return envelope({
            'schemaVersion': 1,
            'credentials': [credentialJson()],
            'supportedKinds': [
              {'kind': 'uuid'},
            ],
          });
        if (request.url.path == '/api/v1/config')
          return envelope({'revision': 4, 'config': configJson()});
        writes++;
        final body = jsonDecode(request.body) as Map<String, Object?>;
        final altered = {
          ...body['payload'] as Map<String, Object?>,
          'listeners': <Object?>[],
        };
        return envelope({
          'id': 'draft_fixture',
          'revision': 2,
          'baseRevision': 4,
          'config': altered,
        }, requestId: body['requestId'] as String);
      });
      addTearDown(api.close);
      await api.restoreSession();
      final credential = (await api.credentialInventory()).credentials.single;
      await expectLater(
        api.prepareNewUuidListener(
          const NewUuidListenerInput(
            listenerId: 'new_listener',
            userId: 'new_user',
            name: 'Test',
            bindAddress: '127.0.0.1',
            port: 18091,
          ),
          credential,
          cmd,
        ),
        throwsA(
          isA<ProductFailure>()
              .having((e) => e.code, 'code', 'DRAFT_CHANGED')
              .having((e) => e.outcomeUnknown, 'unknown', isTrue),
        ),
      );
      expect(writes, 1);
    },
  );

  for (final deleting in [false, true]) {
    test(
      'existing listener ${deleting ? 'delete' : 'edit'} rejects changed draft receipt',
      () async {
        var writes = 0;
        final api = apiFor((request) async {
          if (request.url.path == '/api/v1/config')
            return envelope({'revision': 4, 'config': configJson()});
          writes++;
          final body = jsonDecode(request.body) as Map<String, Object?>;
          return envelope({
            'id': 'draft_fixture',
            'revision': 2,
            'baseRevision': 4,
            'config': configJson(),
          }, requestId: body['requestId'] as String);
        });
        addTearDown(api.close);
        await api.restoreSession();
        final operation = deleting
            ? api.planDeleteListener('listener_fixture', cmd)
            : api.planListener(
                const ListenerDraft(
                  listenerId: 'listener_fixture',
                  name: 'Changed name',
                  presetKey: 'vless',
                  bind: '127.0.0.1',
                  port: 18090,
                  enabled: true,
                ),
                cmd,
              );
        await expectLater(
          operation,
          throwsA(
            isA<ProductFailure>()
                .having((e) => e.code, 'code', 'DRAFT_CHANGED')
                .having((e) => e.outcomeUnknown, 'unknown', isTrue),
          ),
        );
        expect(writes, 1);
      },
    );
  }
  test(
    'malformed success receipt after credential POST stays unknown',
    () async {
      final api = apiFor(
        (request) async => envelope({
          'schemaVersion': 1,
          'id': 'credential_fixture',
        }, requestId: cmd.requestId),
      );
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.generateUuidCredential(cmd),
        throwsA(
          isA<ProductFailure>()
              .having((e) => e.outcomeUnknown, 'unknown', isTrue)
              .having(
                (e) => e.definitelyNotApplied,
                'not a proven rejection',
                isFalse,
              ),
        ),
      );
    },
  );

  test(
    'invalid local publication input rejects before HTTP, not uncertain',
    () async {
      var writes = 0;
      final api = apiFor((request) async {
        writes++;
        return envelope(null);
      });
      addTearDown(api.close);
      await api.restoreSession();
      await expectLater(
        api.createPublication(
          PublicationDraft(name: 'Test', enabled: true, sources: []),
          cmd,
        ),
        throwsA(
          isA<ProductFailure>().having(
            (e) => e.definitelyNotApplied,
            'not sent',
            isTrue,
          ),
        ),
      );
      expect(writes, 0);
    },
  );
}

// Canonical-shape, safe fixtures for the actual config + observation projection.
Map<String, Object?> listenerJson() => {
  'schemaVersion': 1,
  'id': 'listener_fixture',
  'name': 'Observed test listener',
  'enabled': true,
  'bind': {'address': '127.0.0.1', 'port': 18090},
  'protocol': {
    'kind': 'proxy',
    'protocol': {'kind': 'vless', 'flow': null},
    'users': [
      {
        'id': 'user_fixture',
        'credentialRef': 'secret:fixture_uuid',
        'enabled': true,
      },
    ],
  },
  'transport': {'kind': 'tcp'},
  'security': {'kind': 'none'},
  'requirements': <String>[],
};
Map<String, Object?> configJson() => {
  'schemaVersion': 1,
  'minimumReaderVersion': 1,
  'nodes': <Object?>[],
  'subscriptions': <Object?>[],
  'listeners': [listenerJson()],
};
Map<String, Object?> observationJson({bool ready = true, int? revision = 2}) =>
    {
      'schemaVersion': 1,
      'desiredRevision': 2,
      'observedRevision': revision,
      'operations': <Object?>[],
      'listeners': [
        {
          'listenerId': 'listener_fixture',
          'generation': 3,
          'status': ready ? 'ready' : 'degraded',
          'bound': true,
          'authenticationLoaded': true,
          'error': null,
          'forwarding': {
            'status': ready ? 'passed' : 'not_run',
            'observedAt': ready ? 1000 : null,
            'evidenceId': ready ? 'evidence_fixture' : null,
            'detailKey': null,
          },
        },
      ],
    };

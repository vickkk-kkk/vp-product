import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';

Map<String, Object?> observation({
  String status = 'passed',
  int? at = 1000,
  String? evidence = 'evidence_test',
}) => {
  'status': status,
  'observedAt': at,
  'evidenceId': evidence,
  'detailKey': null,
};
Map<String, Object?> runtimeFixture() => {
  'schemaVersion': 1,
  'instanceId': 'test-instance',
  'generation': 1,
  'sequence': 1,
  'observedAt': 1000,
  'validUntil': 2000,
  'desired': {'kind': 'connected', 'nodeId': 'node_test'},
  'phase': 'connected',
  'configRevision': 3,
  'desiredRevision': 3,
  'nodeId': 'node_test',
  'operationId': null,
  'health': <String, Object?>{
    for (final key in [
      'core',
      'takeover',
      'tunnel',
      'dns',
      'ipv4',
      'ipv6',
      'forwarding',
    ])
      key: observation(),
    'requiredProbes': ['dns', 'ipv4'],
  },
  'error': null,
};
void main() {
  test(
    'canonical shared idle fixture is consumed without fabricated readiness',
    () {
      final json =
          jsonDecode(
                File(
                  '../../../contracts/fixtures/runtime-idle.json',
                ).readAsStringSync(),
              )
              as Map<String, dynamic>;
      final dto = RuntimeSnapshotDto.fromJson(json);
      expect(dto.phase, 'idle');
      expect(dto.toView().isVerified, isFalse);
      expect(dto.desiredNodeId, isNull);
    },
  );
  test('opaque identifiers cannot carry paths or credential URLs', () {
    final json = runtimeFixture()
      ..['operationId'] = 'https://secret.invalid/token';
    expect(
      () => RuntimeSnapshotDto.fromJson(json),
      throwsA(isA<ProductFailure>()),
    );
  });

  final now = DateTime.fromMillisecondsSinceEpoch(1500, isUtc: true);
  test(
    'verified requires current identity, revision and actual required observations',
    () {
      final dto = RuntimeSnapshotDto.fromJson(runtimeFixture());
      expect(dto.connectionVerifiedAt(now), isTrue);
      expect(dto.toView(now: now).isVerified, isTrue);
      expect(dto.toView(now: now).canConnect, isFalse); // policy never inferred
    },
  );
  test('process started alone is not verified', () {
    final json = runtimeFixture();
    final health = json['health']! as Map<String, Object?>;
    health['forwarding'] = observation(
      status: 'not_run',
      at: null,
      evidence: null,
    );
    expect(
      RuntimeSnapshotDto.fromJson(json).connectionVerifiedAt(now),
      isFalse,
    );
  });
  test('different actual revision cannot appear verified', () {
    final json = runtimeFixture()..['configRevision'] = 2;
    expect(
      RuntimeSnapshotDto.fromJson(json).connectionVerifiedAt(now),
      isFalse,
    );
  });
  test('old node success cannot verify the new desired node', () {
    final json = runtimeFixture()
      ..['desired'] = {'kind': 'connected', 'nodeId': 'node_other'};
    expect(
      RuntimeSnapshotDto.fromJson(json).connectionVerifiedAt(now),
      isFalse,
    );
  });
  test('expired observations cannot be green', () {
    final dto = RuntimeSnapshotDto.fromJson(runtimeFixture());
    expect(
      dto.connectionVerifiedAt(
        DateTime.fromMillisecondsSinceEpoch(2000, isUtc: true),
      ),
      isFalse,
    );
  });
  test('future snapshot cannot be green', () {
    expect(
      RuntimeSnapshotDto.fromJson(runtimeFixture()).connectionVerifiedAt(
        DateTime.fromMillisecondsSinceEpoch(999, isUtc: true),
      ),
      isFalse,
    );
  });
  test('a passed flag without evidence identifier cannot verify', () {
    final json = runtimeFixture();
    (json['health']! as Map<String, Object?>)['takeover'] = observation(
      evidence: null,
    );
    expect(
      RuntimeSnapshotDto.fromJson(json).connectionVerifiedAt(now),
      isFalse,
    );
  });
  test('required DNS failure is degraded, not a generic success', () {
    final json = runtimeFixture();
    (json['health']! as Map<String, Object?>)['dns'] = observation(
      status: 'failed',
    );
    expect(
      RuntimeSnapshotDto.fromJson(json).toView(now: now).phase,
      ConnectionPhase.degraded,
    );
  });
  test('unknown schema is rejected rather than read/write downgraded', () {
    expect(
      () =>
          RuntimeSnapshotDto.fromJson(runtimeFixture()..['schemaVersion'] = 2),
      throwsA(isA<ProductFailure>()),
    );
  });
  test('unknown probe is rejected rather than ignored', () {
    final json = runtimeFixture();
    (json['health']! as Map<String, Object?>)['requiredProbes'] = [
      'future_required_probe',
    ];
    expect(
      () => RuntimeSnapshotDto.fromJson(json),
      throwsA(isA<ProductFailure>()),
    );
  });
  test('unclassified mutation failure remains uncertain', () {
    expect(
      safeMutationFailure(StateError('raw secret-bearing text')).outcomeUnknown,
      isTrue,
    );
    expect(
      safeMutationFailure(StateError('raw secret-bearing text')).message,
      isNot(contains('secret-bearing')),
    );
  });
  test('only explicit definitely-not-applied evidence unlocks submission', () {
    expect(
      safeMutationFailure(
        const ProductFailure(
          'NO_ADAPTER',
          'Not available',
          definitelyNotApplied: true,
        ),
      ).outcomeUnknown,
      isFalse,
    );
  });
}

import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/src/state.dart';

// Characterize the existing pure contracts before feature stores are migrated.
// These tests do not imply that MVI, effect delivery, or a native VPN is wired.
void main() {
  const identity = MutationIdentity(
    requestId: 'request_original',
    idempotencyKey: 'key_original',
    expectedRevision: 'revision_original',
  );
  const failure = ProductFailure('TEST_ONLY', 'Synthetic safe error');

  test('initial reads have no last-good value', () {
    expect(const Loading<String>().previous, isNull);
    expect(const LoadFailed<String>(failure).previous, isNull);
  });

  test('loading and failure retain last-good without becoming loaded', () {
    const loaded = Loaded('revisioned value');
    final loading = Loading(loaded.previous);
    final failed = LoadFailed(failure, loading.previous);

    expect(loading.previous, loaded.value);
    expect(failed.previous, loaded.value);
    expect(loading, isNot(isA<Loaded<String>>()));
    expect(failed, isNot(isA<Loaded<String>>()));
  });

  test('only running and uncertain mutations block a fresh submission', () {
    const cases = <MutationState, bool>{
      MutationIdle(): false,
      MutationRunning('Submitting', identity): true,
      MutationSucceeded('Accepted', 'operation_original'): false,
      MutationFailed(failure): false,
      MutationUncertain(failure, identity): true,
    };
    for (final entry in cases.entries) {
      expect(
        entry.key.blocked,
        entry.value,
        reason: '${entry.key.runtimeType}',
      );
    }
  });

  test('uncertain retains the exact original identity and revision', () {
    const running = MutationRunning('Submitting', identity);
    final uncertain = MutationUncertain(failure, running.identity);

    expect(uncertain.identity, same(identity));
    expect(uncertain.identity.requestId, 'request_original');
    expect(uncertain.identity.idempotencyKey, 'key_original');
    expect(uncertain.identity.expectedRevision, 'revision_original');
  });

  test('read-error flags cannot unlock an uncertain command', () {
    // Reconciliation may fail with a read error rather than a mutation error.
    // The pending state's type, not retryable/outcomeUnknown, owns this gate.
    for (final retryable in [false, true]) {
      for (final outcomeUnknown in [false, true]) {
        final state = MutationUncertain(
          ProductFailure(
            'RECONCILE_READ_FAILED',
            'Synthetic safe error',
            retryable: retryable,
            outcomeUnknown: outcomeUnknown,
          ),
          identity,
        );
        expect(state.blocked, isTrue);
        expect(state.identity, same(identity));
      }
    }
  });

  test('successful read replacement does not resolve uncertain mutation', () {
    const pending = MutationUncertain(failure, identity);
    LoadState<String> observation = const Loading('old observation');
    observation = const Loaded('new observation');

    expect(observation.previous, 'new observation');
    expect(pending.blocked, isTrue);
    expect(pending.identity, same(identity));
  });
}

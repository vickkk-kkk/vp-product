import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';
import 'fixtures.dart';

void main() {
  late PublicationFixtureApi api;
  late PublicationController controller;
  setUp(() async {
    api = PublicationFixtureApi();
    controller = PublicationController(api, api);
    await controller.refresh();
  });
  tearDown(() {
    if (!controller.disposed) controller.dispose();
  });
  test(
    'generator capability is actual; repeated press has one mutation',
    () async {
      api.workspace = fixtureWorkspace(supported: false);
      await controller.refresh();
      await controller.generateCredential();
      expect(api.generationCommands, isEmpty);
      api.workspace = fixtureWorkspace();
      await controller.refresh();
      api.pendingCredential = Completer();
      final action = controller.generateCredential();
      await controller.generateCredential();
      expect(api.generationCommands, hasLength(1));
      api.pendingCredential!.complete(fixtureCredential);
      await action;
      expect(controller.generatedCredential, same(fixtureCredential));
      expect(controller.completedActions, 1);
      expect(controller.preparedPlan, isNull);
    },
  );
  test(
    'timeout blocks new key; readonly refresh never unlocks; explicit retry preserves identity',
    () async {
      api.generationFailure = TimeoutException(
        'untrusted-secret-do-not-display',
      );
      await controller.generateCredential();
      final original = api.generationCommands.single;
      expect(controller.mutation, isA<MutationUncertain>());
      await controller.refresh();
      await controller.generateCredential();
      expect(api.generationCommands, hasLength(1));
      api.generationFailure = null;
      await controller.retryOriginal();
      expect(
        api.generationCommands.last.idempotencyKey,
        original.idempotencyKey,
      );
      expect(api.generationCommands.last.requestId, original.requestId);
      expect(controller.completedActions, 1);
    },
  );
  test(
    'only explicit definitely-not-applied rejection permits new command',
    () async {
      api.generationFailure = const ProductFailure(
        'VALIDATION',
        '拒绝',
        definitelyNotApplied: true,
      );
      await controller.generateCredential();
      expect(controller.mutation, isA<MutationFailed>());
      api.generationFailure = null;
      await controller.generateCredential();
      expect(api.generationCommands, hasLength(2));
      expect(
        api.generationCommands.first.idempotencyKey,
        isNot(api.generationCommands.last.idempotencyKey),
      );
    },
  );
  test(
    'session change clears display data, suppresses late credential, blocks cross-session replay',
    () async {
      api.pendingCredential = Completer();
      final action = controller.generateCredential();
      api.changeSession();
      api.pendingCredential!.complete(fixtureCredential);
      await action;
      expect(controller.generatedCredential, isNull);
      expect(controller.state.previous, isNull);
      expect(controller.mutation, isA<MutationUncertain>());
      expect(controller.canRetryOriginal, isFalse);
      await controller.retryOriginal();
      expect(api.generationCommands, hasLength(1));
    },
  );
  test('late metadata cannot populate a new session', () async {
    api.pendingRead = Completer();
    final read = controller.refresh();
    api.changeSession();
    api.pendingRead!.complete(fixtureWorkspace());
    await read;
    expect(controller.state.previous, isNull);
  });
  test(
    'secret is a direct one-shot handoff, never ordinary state; rapid issue is single',
    () async {
      api.pendingIssue = Completer();
      final action = controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      expect(
        await controller.issue(
          fixturePublication(),
          3600,
          explicitlyConfirmed: true,
        ),
        isNull,
      );
      expect(api.issueCommands, hasLength(1));
      final secret = fixtureSecret(api.epoch);
      api.pendingIssue!.complete(secret);
      expect(await action, same(secret));
      expect(controller.state.toString(), isNot(contains(syntheticIssuedUrl)));
      expect(controller.notice, isNot(contains(syntheticIssuedUrl)));
      expect(secret.toString(), isNot(contains(syntheticIssuedUrl)));
      expect(secret.takeOnce(), syntheticIssuedUrl);
      expect(secret.takeOnce(), isNull);
    },
  );
  test(
    'unknown issue does not retry; metadata then explicit new rotation is required',
    () async {
      api.issuanceFailure = TimeoutException('raw');
      expect(
        await controller.issue(
          fixturePublication(),
          3600,
          explicitlyConfirmed: true,
        ),
        isNull,
      );
      final original = api.issueCommands.single;
      await controller.retryOriginal();
      expect(api.issueCommands, hasLength(1));
      await controller.refresh();
      expect(controller.blocked, isTrue);
      expect(
        await controller.issue(
          fixturePublication(revision: 2),
          3600,
          explicitlyConfirmed: true,
          replaceUnknown: true,
        ),
        isNull,
      );
      await controller.readIssueMetadata();
      expect(api.metadataReads, 1);
      expect(api.issueCommands, hasLength(1));
      api.issuanceFailure = null;
      final result = await controller.issue(
        controller.issueRecovery!.metadata!,
        3600,
        explicitlyConfirmed: true,
        replaceUnknown: true,
      );
      expect(result, isNotNull);
      result!.dispose();
      expect(
        api.issueCommands.last.idempotencyKey,
        isNot(original.idempotencyKey),
      );
      expect(api.issueCommands.last.expectedRevision, '2');
    },
  );
  test(
    'SECRET_RESULT_UNAVAILABLE stays blocked even if error stage says rejected',
    () async {
      api.issuanceFailure = const ProductFailure(
        'SECRET_RESULT_UNAVAILABLE',
        '不可取回',
        definitelyNotApplied: true,
      );
      await controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      expect(controller.issueRecovery, isNotNull);
      expect(controller.blocked, isTrue);
      expect(controller.canRetryOriginal, isFalse);
    },
  );
  test(
    'failed explicit replacement does not forget older uncertain issuance',
    () async {
      api.issuanceFailure = TimeoutException('raw');
      await controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      await controller.readIssueMetadata();
      final original = controller.issueRecovery;
      api.issuanceFailure = const ProductFailure(
        'REVISION_CONFLICT',
        '已变化',
        definitelyNotApplied: true,
      );
      await controller.issue(
        original!.metadata!,
        3600,
        explicitlyConfirmed: true,
        replaceUnknown: true,
      );
      expect(controller.issueRecovery, same(original));
      expect(controller.blocked, isTrue);
    },
  );
  test(
    'focus loss during issuance drops result rather than displaying late link',
    () async {
      api.pendingIssue = Completer();
      final action = controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      controller.setForeground(false);
      final secret = fixtureSecret(api.epoch);
      api.pendingIssue!.complete(secret);
      expect(await action, isNull);
      expect(secret.isAvailable, isFalse);
      expect(controller.issueRecovery, isNotNull);
    },
  );
  test(
    'dispose and session loss invalidate in-flight sensitive result',
    () async {
      api.pendingIssue = Completer();
      final action = controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      controller.dispose();
      final secret = fixtureSecret(api.epoch);
      api.pendingIssue!.complete(secret);
      expect(await action, isNull);
      expect(secret.isAvailable, isFalse);
    },
  );
  test(
    'stale active revision cannot publish or issue through direct controller call',
    () async {
      api.workspace = fixtureWorkspace(observed: null);
      await controller.refresh();
      await controller.create(
        PublicationDraft(
          name: 'test',
          enabled: true,
          sources: fixturePublication().sources,
        ),
      );
      expect(
        await controller.issue(
          fixturePublication(),
          3600,
          explicitlyConfirmed: true,
        ),
        isNull,
      );
      expect(api.creates, 0);
      expect(api.issueCommands, isEmpty);
    },
  );
  test(
    'metadata recovery never automatically rotates after read error',
    () async {
      api.issuanceFailure = TimeoutException('raw');
      await controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      api.metadataFailure = StateError('raw');
      await controller.readIssueMetadata();
      expect(controller.recoveryReadError, isNotNull);
      expect(controller.issueRecovery!.metadata, isNull);
      expect(api.issueCommands, hasLength(1));
    },
  );
  test(
    'a rejected retry cannot erase the first request unknown outcome',
    () async {
      api.generationFailure = TimeoutException('raw');
      await controller.generateCredential();
      final original = controller.pending!.identity;
      api.generationFailure = const ProductFailure(
        'REVISION_CONFLICT',
        '拒绝本次重试',
        definitelyNotApplied: true,
      );
      await controller.retryOriginal();
      expect(controller.mutation, isA<MutationUncertain>());
      expect(
        controller.pending!.identity.idempotencyKey,
        original.idempotencyKey,
      );
      expect(controller.blocked, isTrue);
    },
  );

  test(
    'focus lost before dispatch is a definite no-send, not permanent busy',
    () async {
      controller.addListener(() {
        if (controller.mutation is MutationRunning)
          controller.setForeground(false);
      });
      expect(
        await controller.issue(
          fixturePublication(),
          3600,
          explicitlyConfirmed: true,
        ),
        isNull,
      );
      expect(api.issueCommands, isEmpty);
      expect(controller.mutation, isA<MutationFailed>());
      expect(controller.blocked, isFalse);
    },
  );
  test(
    'undisplayed handoff is disposed and recovery contains only safe metadata',
    () async {
      final secret = await controller.issue(
        fixturePublication(),
        3600,
        explicitlyConfirmed: true,
      );
      controller.discardUndisplayedSecret(secret!);
      expect(secret.isAvailable, isFalse);
      expect(controller.issueRecovery, isNotNull);
      expect(
        controller.issueRecovery.toString(),
        isNot(contains(syntheticIssuedUrl)),
      );
    },
  );
}

import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';
import 'fixtures/ports.dart';

void main() {
  test(
    'editing and late cancelled parse release only their native preview',
    () async {
      final importer = LifecycleImporter();
      final controller = ImportController(importer);
      final preview = ImportPreview(
        id: 'preview-secret',
        baseRevision: '1',
        items: const [],
        warnings: const [],
        expiresAt: DateTime.now().add(const Duration(minutes: 10)),
        isNodeExtraction: false,
        requiresExplicitNodeExtraction: false,
      );
      controller.state = ImportReview(preview);
      controller.edit();
      expect(importer.discarded, ['preview-secret']);
      final parsing = controller.parse('synthetic', '1');
      controller.cancelParsing();
      importer.parsed.complete(preview);
      await parsing;
      expect(importer.discarded, ['preview-secret', 'preview-secret']);
      expect(controller.state, isA<ImportEditing>());
      controller.dispose();
    },
  );

  test(
    'logout discards late session data but keeps unknown command identity',
    () async {
      final api = TestManagement()..pendingApply = Completer<OperationView>();
      final controller = AdminController(api);
      addTearDown(controller.dispose);
      await controller.refresh();
      controller.plan = ChangePlan(
        id: 'plan_1',
        hash: 'a' * 64,
        baseRevision: '1',
        target: 'test',
        changes: const [],
        impacts: const [],
        recovery: 'test',
        expiresAt: DateTime.now().add(const Duration(minutes: 2)),
        confirmationPhrase: 'apply',
      );
      final applying = controller.apply('apply');
      final identity = (controller.mutation as MutationRunning).identity;
      controller.forgetSession();
      expect(controller.state, isA<LoadFailed<ManagementSnapshot>>());
      expect((controller.state as LoadFailed).error.code, 'AUTH_REQUIRED');
      expect(controller.state.previous, isNull);
      expect(controller.plan, isNull);
      expect(
        (controller.mutation as MutationUncertain).identity.idempotencyKey,
        identity.idempotencyKey,
      );
      api.pendingApply!.complete(
        const OperationView(
          id: 'operation_1',
          stage: 'commit',
          status: 'succeeded',
          lastMessage: 'test',
          cancellable: false,
          terminal: true,
        ),
      );
      await applying;
      expect(controller.activeOperation, isNull);
      expect(controller.mutation, isA<MutationUncertain>());
    },
  );

  test(
    'refresh failure preserves last inventory and prevents mutation',
    () async {
      final repository = TestRepository();
      final controller = InventoryController(repository);
      addTearDown(controller.dispose);
      await controller.refresh();
      repository.readError = StateError('test');
      await controller.refresh();
      expect(controller.state, isA<LoadFailed<Revisioned<ClientInventory>>>());
      expect(controller.state.previous!.revision, '1');
      await controller.mutate(
        'rename',
        (command) => repository.renameNode('node:test', 'name', command),
      );
      expect(repository.mutations, 0);
    },
  );
  test('repeated clicks create one command', () async {
    final repository = TestRepository()..pending = Completer<MutationReceipt>();
    final controller = InventoryController(repository);
    addTearDown(controller.dispose);
    await controller.refresh();
    final first = controller.mutate(
      'rename',
      (command) => repository.renameNode('node:test', 'name', command),
    );
    await controller.mutate(
      'rename',
      (command) => repository.renameNode('node:test', 'name', command),
    );
    expect(repository.mutations, 1);
    repository.pending!.complete(
      const MutationReceipt(operationId: 'operation:one', revision: '2'),
    );
    await first;
  });
  test(
    'timeout cannot unlock a new mutation key; null reconcile stays blocked',
    () async {
      final repository = TestRepository()
        ..pending = Completer<MutationReceipt>();
      final controller = InventoryController(repository);
      addTearDown(controller.dispose);
      await controller.refresh();
      final pending = controller.mutate(
        'rename',
        (command) => repository.renameNode('node:test', 'name', command),
      );
      repository.pending!.completeError(TimeoutException('not known'));
      await pending;
      expect(controller.mutation, isA<MutationUncertain>());
      await controller.reconcile();
      expect(controller.mutation.blocked, isTrue);
      await controller.mutate(
        'rename',
        (command) => repository.renameNode('node:test', 'name', command),
      );
      expect(repository.mutations, 1);
    },
  );
  test('accepted connect does not synthesize connected state', () async {
    final runtime = TestRuntime();
    final controller = ConnectionController(runtime);
    addTearDown(() async {
      controller.dispose();
      await runtime.stream.close();
    });
    await controller.refresh();
    await controller.command(
      'connect',
      (command) => runtime.connect(nodeId: 'node:test', command: command),
    );
    expect(controller.state.previous!.phase, ConnectionPhase.disconnected);
    expect(runtime.lastCommand!.idempotencyKey, isNotEmpty);
  });
  test('stale observation cannot overwrite a newer generation', () async {
    final runtime = TestRuntime()
      ..current = connection(generation: 2, sequence: 5);
    final controller = ConnectionController(runtime);
    addTearDown(() async {
      controller.dispose();
      await runtime.stream.close();
    });
    await controller.refresh();
    runtime.stream.add(
      RuntimeObservation(
        connection(generation: 1, sequence: 6, phase: ConnectionPhase.verified),
      ),
    );
    await Future<void>.delayed(Duration.zero);
    expect(controller.state.previous!.generation, 2);
    expect(controller.state.previous!.phase, ConnectionPhase.disconnected);
  });
  test(
    'late parse after cancellation cannot restore preview or save',
    () async {
      final service = TestImporter();
      final controller = ImportController(service);
      addTearDown(controller.dispose);
      final parsing = controller.parse('test-only text', '1');
      controller.cancelParsing();
      service.parsed.complete(preview());
      await parsing;
      expect(controller.state, isA<ImportEditing>());
      expect(service.commits, 0);
    },
  );
  test('malformed preview item cannot be forced into commit', () async {
    final service = TestImporter();
    final controller = ImportController(service);
    addTearDown(controller.dispose);
    controller.state = ImportReview(preview());
    await controller.commit(
      const ImportSelection(
        selectedIds: {'entry:2'},
        duplicates: {},
        acceptNodeExtraction: false,
      ),
    );
    expect(service.commits, 0);
    expect((controller.state as ImportReview).error, isNotNull);
  });
  test('unknown import outcome cannot be re-committed', () async {
    final service = TestImporter()..commitError = TimeoutException('test');
    final controller = ImportController(service);
    addTearDown(controller.dispose);
    controller.state = ImportReview(preview());
    const selection = ImportSelection(
      selectedIds: {'entry:1'},
      duplicates: {},
      acceptNodeExtraction: false,
    );
    await controller.commit(selection);
    await controller.commit(selection);
    await controller.reconcile();
    expect(service.commits, 1);
    expect(controller.state, isA<ImportUncertain>());
  });
  test('expired plan never reaches apply', () async {
    final api = TestManagement();
    final controller = AdminController(api);
    addTearDown(controller.dispose);
    await controller.refresh();
    controller.plan = ChangePlan(
      id: 'plan:test',
      hash: 'hash',
      baseRevision: '1',
      target: 'Test host',
      changes: const [],
      impacts: const [],
      recovery: 'test',
      expiresAt: DateTime.now().subtract(const Duration(seconds: 1)),
      confirmationPhrase: 'apply',
    );
    await controller.apply('apply');
    expect(api.applications, 0);
    expect(controller.plan, isNull);
  });
  test(
    'unclassified apply failure remains uncertain after reconcile',
    () async {
      final api = TestManagement()..applyError = TimeoutException('test');
      final controller = AdminController(api);
      addTearDown(controller.dispose);
      await controller.refresh();
      controller.plan = ChangePlan(
        id: 'plan:test',
        hash: 'hash',
        baseRevision: '1',
        target: 'Test host',
        changes: const [],
        impacts: const [],
        recovery: 'test',
        expiresAt: DateTime.now().add(const Duration(minutes: 1)),
        confirmationPhrase: 'apply',
      );
      await controller.apply('apply');
      await controller.reconcile();
      await controller.apply('apply');
      expect(api.applications, 1);
      expect(controller.mutation, isA<MutationUncertain>());
    },
  );
  test(
    'runtime timeout preserves the original pending command and blocks retry',
    () async {
      final runtime = TestRuntime()..connectError = TimeoutException('test');
      final controller = ConnectionController(runtime);
      addTearDown(() async {
        controller.dispose();
        await runtime.stream.close();
      });
      await controller.refresh();
      await controller.command(
        'connect',
        (command) => runtime.connect(nodeId: 'node:test', command: command),
      );
      final key =
          (controller.mutation as MutationUncertain).identity.idempotencyKey;
      await controller.reconcile();
      await controller.command(
        'connect',
        (command) => runtime.connect(nodeId: 'node:test', command: command),
      );
      expect(runtime.connects, 1);
      expect(
        (controller.mutation as MutationUncertain).identity.idempotencyKey,
        key,
      );
    },
  );
  test(
    'cancel timeout plus failed poll never unlocks a second cancellation',
    () async {
      final api = TestManagement()
        ..cancelError = TimeoutException('cancel')
        ..operationError = TimeoutException('poll');
      final controller = AdminController(api);
      addTearDown(controller.dispose);
      await controller.refresh();
      controller.activeOperation = OperationView(
        id: 'operation:test',
        stage: 'stage',
        status: 'running',
        lastMessage: 'Test only',
        cancellable: true,
        terminal: false,
      );
      await controller.cancelOperation();
      expect(controller.mutation, isA<MutationUncertain>());
      await controller.openOperation('operation:test');
      expect(controller.mutation, isA<MutationUncertain>());
      expect(controller.operationReadError, isNotNull);
      await controller.cancelOperation();
      expect(api.cancellations, 1);
      expect(api.cancelIdentity!.idempotencyKey, isNotEmpty);
    },
  );
}

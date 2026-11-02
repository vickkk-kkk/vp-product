import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/src/controllers.dart';
import 'package:vp_features/src/state.dart';
import 'fixtures/ports.dart';

class ObservedRuntime extends TestRuntime {
  int reads = 0;
  Completer<ConnectionView>? gate;
  bool failRead = false;
  String? reconciledKey;
  String? reconciliation;
  @override
  Future<String?> reconcile(String idempotencyKey) async {
    reconciledKey = idempotencyKey;
    return reconciliation;
  }

  @override
  Future<ConnectionView> snapshot() async {
    reads++;
    if (failRead) throw const ProductFailure('READ_FAILED', 'Test only');
    return gate?.future ?? connection(sequence: reads);
  }
}

void main() {
  test(
    'unknown connect retains exact sent inventory identity and target across snapshot refresh and reconcile',
    () async {
      final runtime = ObservedRuntime()
        ..connectError = const ProductFailure(
          'TIMEOUT',
          'Test unknown',
          outcomeUnknown: true,
        );
      final controller = ConnectionController(runtime);
      await controller.refresh();
      const node = NodeView(
        id: 'intended-node',
        name: 'Test',
        endpoint: '10.0.2.2:18080',
        protocolLabel: 'SOCKS',
        transportLabel: 'TCP',
        sourceLabel: 'Test',
        capability: CapabilityView(
          key: 'test',
          label: 'Test',
          status: CapabilityStatus.certified,
          reason: 'Test fixture only',
          evidenceIds: ['fixture'],
        ),
      );
      await controller.connectNode(
        node: node,
        inventoryRevision: 'opaque-inventory-not-runtime-revision',
      );
      final sent = runtime.lastCommand!;
      final uncertain = controller.mutation as MutationUncertain;
      expect(uncertain.identity, same(sent));
      expect(sent.expectedRevision, 'opaque-inventory-not-runtime-revision');
      expect(controller.mutationNodeId, 'intended-node');
      await controller.refresh();
      expect((controller.mutation as MutationUncertain).identity, same(sent));
      await controller.connectNode(
        node: node,
        inventoryRevision: 'newer-inventory',
      );
      expect(runtime.connects, 1);
      await controller.reconcile();
      expect(runtime.reconciledKey, sent.idempotencyKey);
      expect(controller.mutation, isA<MutationUncertain>());
      expect(controller.mutationNodeId, 'intended-node');
      runtime.reconciliation = 'accepted-original';
      await controller.reconcile();
      expect(runtime.reconciledKey, sent.idempotencyKey);
      expect(
        (controller.mutation as MutationSucceeded).operationId,
        'accepted-original',
      );
      expect(runtime.connects, 1);
      controller.dispose();
      await runtime.dispose();
    },
  );
  test(
    'simultaneous reads share one native request and never reset uncertain mutation',
    () async {
      final runtime = ObservedRuntime()..gate = Completer<ConnectionView>();
      final controller = ConnectionController(runtime);
      final identity = identityFor('opaque');
      controller.mutation = MutationUncertain(
        const ProductFailure('TIMEOUT', 'Test only', outcomeUnknown: true),
        identity,
      );
      final first = controller.refresh();
      final second = controller.refresh();
      expect(identical(first, second), true);
      expect(runtime.reads, 1);
      expect(controller.isRefreshing, true);
      runtime.gate!.complete(connection());
      await first;
      expect(controller.isRefreshing, false);
      expect(controller.mutation, isA<MutationUncertain>());
      expect(
        (controller.mutation as MutationUncertain).identity,
        same(identity),
      );
      controller.dispose();
      await runtime.dispose();
    },
  );

  testWidgets(
    'visible lease polls, pauses fully offscreen and refreshes on return',
    (tester) async {
      final runtime = ObservedRuntime();
      final controller = ConnectionController(runtime);
      controller.setObservationActive(true);
      await tester.pump();
      expect(runtime.reads, 1);
      await tester.pump(const Duration(seconds: 10));
      expect(runtime.reads, 2);
      // Stream cancellation may complete a cached Future in the root zone.
      await tester.runAsync(() => Future<void>.delayed(Duration.zero));
      await tester.pump();
      controller.setObservationActive(false);
      await tester.pump(const Duration(minutes: 2));
      expect(runtime.reads, 2);
      controller.setObservationActive(true);
      await tester.pump();
      await tester.pump();
      expect(runtime.reads, 3);
      controller.dispose();
      await runtime.dispose();
      await tester.pump(const Duration(minutes: 2));
      expect(runtime.reads, 3);
    },
  );

  testWidgets(
    'read failures back off without enabling new uncertain mutation',
    (tester) async {
      final runtime = ObservedRuntime()..failRead = true;
      final controller = ConnectionController(runtime);
      controller.setObservationActive(true);
      await tester.pump();
      expect(runtime.reads, 1);
      await tester.pump(const Duration(seconds: 19));
      expect(runtime.reads, 1);
      await tester.pump(const Duration(seconds: 1));
      expect(runtime.reads, 2);
      await tester.pump(const Duration(seconds: 39));
      expect(runtime.reads, 2);
      await tester.pump(const Duration(seconds: 1));
      expect(runtime.reads, 3);
      await tester.pump(const Duration(seconds: 59));
      expect(runtime.reads, 3);
      await tester.pump(const Duration(seconds: 1));
      expect(runtime.reads, 4);
      controller.setObservationActive(false);
      runtime.failRead = false;
      controller.setObservationActive(true);
      await tester.pump();
      expect(runtime.reads, 5);
      await tester.pump(const Duration(seconds: 10));
      expect(runtime.reads, 6);
      controller.dispose();
      await runtime.dispose();
    },
  );
}

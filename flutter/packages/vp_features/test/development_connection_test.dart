import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/vp_features.dart';
import 'fixtures/ports.dart';

NodeView node(CapabilityStatus status) => NodeView(
  id: 'test-node',
  name: 'Pending test node',
  endpoint: '10.0.2.2:18080',
  protocolLabel: 'SOCKS5',
  transportLabel: 'TCP',
  sourceLabel: 'Test only',
  capability: CapabilityView(
    key: 'test',
    label: 'Test',
    status: status,
    reason: 'Platform acceptance pending',
  ),
);

class PendingRuntime extends TestRuntime {
  final accepted = Completer<String>();
  @override
  Future<String> connect({
    required String nodeId,
    required MutationIdentity command,
  }) {
    connects++;
    lastCommand = command;
    return accepted.future;
  }
}

void main() {
  test(
    'normal path never starts a pending preset; opt-in never changes certification',
    () async {
      final runtime = TestRuntime();
      final controller = ConnectionController(runtime);
      await controller.refresh();
      final pending = node(CapabilityStatus.pending);
      await controller.connectNode(node: pending, inventoryRevision: '23');
      expect(runtime.connects, 0);
      expect(pending.capability.runnable, false);
      expect(
        developmentConnectionEligible(pending.capability),
        developmentConnectionsEnabled,
      );
      expect(
        developmentConnectionEligible(
          node(CapabilityStatus.unsupported).capability,
        ),
        false,
      );
      controller.dispose();
      await runtime.dispose();
    },
  );

  test(
    'development opt-in preserves revision, duplicate guard and request identity',
    () async {
      final runtime = PendingRuntime();
      final controller = ConnectionController(runtime);
      await controller.refresh();
      final first = controller.connectNode(
        node: node(CapabilityStatus.pending),
        inventoryRevision: '23',
        development: true,
      );
      final identity = runtime.lastCommand;
      await controller.connectNode(
        node: node(CapabilityStatus.pending),
        inventoryRevision: '23',
        development: true,
      );
      expect(runtime.connects, developmentConnectionsEnabled ? 1 : 0);
      if (developmentConnectionsEnabled) {
        expect(identity!.expectedRevision, '23');
        expect(runtime.lastCommand, same(identity));
        expect(controller.mutation, isA<MutationRunning>());
      }
      runtime.accepted.complete('test-operation');
      await first;
      expect(controller.state.previous!.phase, ConnectionPhase.disconnected);
      controller.dispose();
      await runtime.dispose();
    },
  );

  testWidgets(
    'pending primary stays disabled unless debug opt-in, which still requires confirmation',
    (tester) async {
      final pending = node(CapabilityStatus.pending);
      final repo = TestRepository()
        ..current = Revisioned(
          revision: '23',
          observedAt: DateTime.now(),
          value: ClientInventory(
            nodes: [pending],
            subscriptions: const [],
            selectedNodeId: pending.id,
          ),
        );
      final runtime = TestRuntime()
        ..current = ConnectionView(
          instanceId: 'test',
          generation: 0,
          sequence: 0,
          phase: ConnectionPhase.disconnected,
          observedAt: DateTime.now(),
          validUntil: DateTime.now().add(const Duration(minutes: 1)),
          evidence: const [],
          summary: 'Test',
          canConnect: true,
          canDisconnect: false,
          canCancel: false,
        );
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            repositoryProvider.overrideWithValue(repo),
            runtimeProvider.overrideWithValue(runtime),
          ],
          child: MaterialApp(
            theme: VpTheme.build(Brightness.light),
            home: const Scaffold(body: ConnectionPage()),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final primary = find.byKey(const ValueKey('connect-node'));
      final control = tester.widget<VpConnectionControl>(primary);
      expect(control.onPressed != null, developmentConnectionsEnabled);
      expect(control.label, developmentConnectionsEnabled ? '测试连接' : '连接');
      final debug = primary;
      if (developmentConnectionsEnabled) {
        await tester.ensureVisible(debug);
        await tester.tap(debug);
        await tester.pumpAndSettle();
        expect(find.text('仅限未认证开发测试'), findsOneWidget);
        expect(runtime.connects, 0);
        await tester.tap(find.text('取消'));
        await tester.pumpAndSettle();
        expect(runtime.connects, 0);
        await tester.tap(debug);
        await tester.pumpAndSettle();
        await tester.tap(find.text('确认测试连接'));
        await tester.pumpAndSettle();
        expect(runtime.connects, 1);
        expect(runtime.lastCommand!.expectedRevision, '23');
        expect(pending.capability.runnable, false);
      }
      await tester.pumpWidget(const SizedBox());
      await runtime.dispose();
    },
  );
}

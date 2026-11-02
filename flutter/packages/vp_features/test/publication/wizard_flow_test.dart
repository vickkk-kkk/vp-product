import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/vp_features.dart';
import 'fixtures.dart';

void main() {
  testWidgets(
    'node wizard generates safe credential, then separate plan confirmation, never fake running',
    (tester) async {
      tester.view.physicalSize = const Size(1100, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final api = PublicationFixtureApi();
      final router = GoRouter(
        initialLocation: '/listeners/new',
        routes: [
          GoRoute(
            path: '/listeners/new',
            builder: (_, __) => const Scaffold(body: NewUuidListenerPage()),
          ),
          GoRoute(
            path: '/maintenance/plan',
            builder: (_, __) => const Scaffold(body: PlanReviewPage()),
          ),
          GoRoute(
            path: '/maintenance/operations/:id',
            builder: (_, state) => Scaffold(
              body: OperationPage(operationId: state.pathParameters['id']!),
            ),
          ),
          GoRoute(
            path: '/listeners',
            builder: (_, __) => const Scaffold(body: ListenerPage()),
          ),
        ],
      );
      addTearDown(router.dispose);
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
          child: MaterialApp.router(
            theme: VpTheme.build(Brightness.light),
            routerConfig: router,
          ),
        ),
      );
      await tester.pumpAndSettle();
      final generate = find.byKey(const ValueKey('generate-node-credential'));
      await tester.ensureVisible(generate);
      await tester.tap(generate);
      await tester.pumpAndSettle();
      expect(api.generationCommands, isEmpty);
      await tester.tap(find.text('取消'));
      await tester.pumpAndSettle();
      expect(api.generationCommands, isEmpty);
      await tester.tap(generate);
      await tester.pumpAndSettle();
      await tester.tap(find.text('确认生成凭据'));
      await tester.pumpAndSettle();
      expect(api.generationCommands, hasLength(1));
      expect(api.applies, 0);
      expect(find.textContaining('secret:fixture_reference'), findsNothing);
      await tester.enterText(find.byType(TextFormField).at(0), '我的回环测试节点');
      await tester.enterText(find.byType(TextFormField).at(1), '19091');
      final consent = find.widgetWithText(
        CheckboxListTile,
        '我仅在回环开发环境验证此未认证组合，不将它当作公网加密服务。',
      );
      await tester.ensureVisible(consent);
      await tester.tap(consent);
      await tester.pump();
      final prepare = find.text('校验草稿并预览计划');
      await tester.ensureVisible(prepare);
      await tester.tap(prepare);
      await tester.pumpAndSettle();
      expect(api.prepares, 1);
      expect(api.preparedInput!.bindAddress, '127.0.0.1');
      expect(api.applies, 0);
      expect(find.text('核对影响，再应用'), findsOneWidget);
      expect(find.textContaining('我的回环测试节点'), findsOneWidget);
      final confirmation = find.byType(TextField);
      await tester.ensureVisible(confirmation);
      await tester.enterText(confirmation, '确认测试计划');
      await tester.pump();
      final apply = find.text('应用已确认计划');
      await tester.ensureVisible(apply);
      await tester.tap(apply);
      await tester.pumpAndSettle();
      expect(api.applies, 1);
      expect(find.text('已连接'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}

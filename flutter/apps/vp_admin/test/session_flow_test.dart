import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_admin/main.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';

// Isolated widget port, never used by production composition.
class TestSession extends UnavailableManagementApi {
  bool signedIn = false;
  int logins = 0, logouts = 0;
  Completer<void>? waiting;
  Object? loginFailure;
  Object? snapshotFailure;
  @override
  bool get canAuthenticate => true;
  @override
  bool get authenticated => signedIn;
  @override
  String get originLabel => 'https://test.invalid';
  @override
  Future<void> login(
    String username,
    String password, {
    String? secondFactor,
  }) async {
    logins++;
    if (waiting != null) await waiting!.future;
    if (loginFailure != null) throw loginFailure!;
    signedIn = true;
  }

  @override
  Future<void> logout() async {
    logouts++;
    signedIn = false;
  }

  @override
  Future<ManagementSnapshot> snapshot() async {
    if (!signedIn) throw const ProductFailure('AUTH_REQUIRED', '请登录。');
    if (snapshotFailure != null) throw snapshotFailure!;
    return ManagementSnapshot(
      hostLabel: 'Widget test only',
      safeManagementOrigin: originLabel,
      revision: '0',
      observedRevision: null,
      observedAt: DateTime.utc(2026),
      listeners: const [],
      presets: const [],
      operations: const [],
    );
  }
}

Future<void> openLogin(WidgetTester tester, TestSession api) async {
  tester.view.physicalSize = const Size(1200, 1000);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    ProviderScope(
      overrides: [managementApiProvider.overrideWithValue(api)],
      child: const VpAdminApp(),
    ),
  );
  await tester.pumpAndSettle();
  expect(find.text('监听'), findsNothing);
}

class DeferredSession extends TestSession {
  final restoration = Completer<void>();
  @override
  Future<ManagementSnapshot> snapshot() async {
    await restoration.future;
    return super.snapshot();
  }
}

void main() {
  testWidgets(
    'business navigation is withheld until actual session restoration',
    (tester) async {
      final api = DeferredSession();
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
          child: const VpAdminApp(),
        ),
      );
      await tester.pump();
      expect(find.text('正在确认管理会话…'), findsOneWidget);
      expect(find.text('监听'), findsNothing);
      expect(find.text('Widget test only'), findsNothing);
      api.signedIn = true;
      api.restoration.complete();
      await tester.pumpAndSettle();
      expect(find.text('Widget test only'), findsOneWidget);
    },
  );
  testWidgets(
    'expired session hides cached workspace; login returns to protected route',
    (tester) async {
      final api = TestSession()..signedIn = true;
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
          child: const VpAdminApp(),
        ),
      );
      await tester.pumpAndSettle();
      final container = ProviderScope.containerOf(
        tester.element(find.byType(AdminOverviewPage)),
      );
      api.signedIn = false;
      await container.read(adminProvider).refresh();
      await tester.pumpAndSettle();
      expect(find.text('Widget test only'), findsNothing);
      expect(find.text('监听'), findsNothing);
      GoRouter.of(
        tester.element(find.byType(ManagementLoginPage)),
      ).go('/listeners');
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextFormField).at(0), 'test_admin');
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'test_only_token',
      );
      await tester.ensureVisible(
        find.byKey(const ValueKey('management-login')),
      );
      await tester.tap(find.byKey(const ValueKey('management-login')));
      await tester.pumpAndSettle();
      expect(find.text('查看协议模板'), findsOneWidget);
      expect(find.byType(ManagementLoginPage), findsNothing);
    },
  );
  testWidgets(
    'failed refresh identifies last known data instead of healthy state',
    (tester) async {
      final api = TestSession()..signedIn = true;
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
          child: const VpAdminApp(),
        ),
      );
      await tester.pumpAndSettle();
      api.snapshotFailure = const ProductFailure(
        'OFFLINE',
        '无法读取服务器状态。',
        retryable: true,
      );
      await ProviderScope.containerOf(
        tester.element(find.byType(AdminOverviewPage)),
      ).read(adminProvider).refresh();
      await tester.pumpAndSettle();
      expect(find.text('以下为上次读取的内容，不代表当前状态；修改操作已暂时停用。'), findsOneWidget);
      expect(find.text('运行修订一致'), findsNothing);
      expect(find.text('Widget test only'), findsOneWidget);
    },
  );
  testWidgets(
    'empty login is local validation and management token stays obscured',
    (tester) async {
      final api = TestSession();
      await openLogin(tester, api);
      await tester.ensureVisible(
        find.byKey(const ValueKey('management-login')),
      );
      await tester.tap(find.byKey(const ValueKey('management-login')));
      await tester.pumpAndSettle();
      expect(api.logins, 0);
      expect(find.text('请输入用户名。'), findsOneWidget);
      final password = tester.widget<TextFormField>(
        find.byType(TextFormField).at(1),
      );
      final field = tester.widget<TextField>(
        find.descendant(
          of: find.byWidget(password),
          matching: find.byType(TextField),
        ),
      );
      expect(field.obscureText, isTrue);
    },
  );
  testWidgets(
    'repeated submit is single request then logout removes cached host',
    (tester) async {
      final api = TestSession()..waiting = Completer<void>();
      await openLogin(tester, api);
      await tester.enterText(find.byType(TextFormField).at(0), 'test_admin');
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'test_only_password',
      );
      final submit = find.byKey(const ValueKey('management-login'));
      await tester.ensureVisible(submit);
      await tester.tap(submit);
      await tester.pump();
      expect(api.logins, 1);
      expect(find.byKey(const ValueKey('management-login')), findsNothing);
      api.waiting!.complete();
      await tester.pumpAndSettle();
      expect(find.text('Widget test only'), findsOneWidget);
      await tester.tap(find.text('管理会话'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.byKey(const ValueKey('management-logout')),
      );
      await tester.tap(find.byKey(const ValueKey('management-logout')));
      await tester.pumpAndSettle();
      expect(api.logouts, 1);
      expect(api.signedIn, isFalse);
      expect(find.text('Widget test only'), findsNothing);
      expect(find.byType(TextFormField), findsNWidgets(2));
      GoRouter.of(
        tester.element(find.byType(ManagementLoginPage)),
      ).go('/listeners');
      await tester.pumpAndSettle();
      expect(find.text('正在确认管理会话…'), findsNothing);
      expect(find.byType(TextFormField), findsNWidgets(2));
      expect(find.text('查看协议模板'), findsNothing);
    },
  );
  testWidgets('failed authentication never reveals raw exception or a server', (
    tester,
  ) async {
    final api = TestSession()
      ..loginFailure = StateError('raw-secret-do-not-display');
    await openLogin(tester, api);
    await tester.enterText(find.byType(TextFormField).at(0), 'test_admin');
    await tester.enterText(
      find.byType(TextFormField).at(1),
      'test_only_password',
    );
    await tester.ensureVisible(find.byKey(const ValueKey('management-login')));
    await tester.tap(find.byKey(const ValueKey('management-login')));
    await tester.pumpAndSettle();
    expect(api.signedIn, isFalse);
    expect(find.textContaining('raw-secret-do-not-display'), findsNothing);
    expect(find.text('Widget test only'), findsNothing);
    expect(find.byKey(const ValueKey('management-login')), findsOneWidget);
  });
  testWidgets(
    'new login cannot expose prior session cache if first read fails',
    (tester) async {
      final api = TestSession()..signedIn = true;
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
          child: const VpAdminApp(),
        ),
      );
      await tester.pumpAndSettle();
      final controller = ProviderScope.containerOf(
        tester.element(find.byType(AdminOverviewPage)),
      ).read(adminProvider);
      api.signedIn = false;
      await controller.refresh();
      await tester.pumpAndSettle();
      api.snapshotFailure = const ProductFailure('OFFLINE', '无法读取服务器状态。');
      await tester.enterText(
        find.byType(TextFormField).at(0),
        'different_test_admin',
      );
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'test_only_token',
      );
      await tester.ensureVisible(
        find.byKey(const ValueKey('management-login')),
      );
      await tester.tap(find.byKey(const ValueKey('management-login')));
      await tester.pumpAndSettle();
      expect(api.signedIn, isTrue);
      expect(controller.state.previous, isNull);
      expect(find.text('Widget test only'), findsNothing);
      expect(find.text('尚未识别服务器'), findsOneWidget);
      expect(find.text('无法读取服务器状态。'), findsOneWidget);
    },
  );
}

// Widget-rendered design proposals. No browser session or running-server proof.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_admin/main.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';
import 'session_flow_test.dart' show TestSession;

class OverviewFixture extends TestSession {
  OverviewFixture() {
    signedIn = true;
  }
  @override
  String get originLabel => 'https://panel.example.invalid';
  @override
  Future<ManagementSnapshot> snapshot() async => ManagementSnapshot(
    hostLabel: '我的独立服务器',
    safeManagementOrigin: originLabel,
    revision: '12',
    observedRevision: null,
    observedAt: DateTime(2026, 10, 30, 14, 32),
    developmentBuild: true,
    listeners: const [
      ListenerView(
        id: 'widget_listener',
        name: '回环开发监听',
        presetKey: 'VLESS · TCP',
        bind: '127.0.0.1',
        port: 18090,
        desiredEnabled: true,
        observedState: '尚未观测',
        desiredRevision: '12',
        observedRevision: null,
      ),
    ],
    presets: const [],
    operations: const [],
  );
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await (FontLoader('packages/vp_design_system/VpSans')..addFont(
          rootBundle.load(
            'packages/vp_design_system/assets/fonts/NotoSansSC-Variable.ttf',
          ),
        ))
        .load();
    await (FontLoader(
      'MaterialIcons',
    )..addFont(rootBundle.load('fonts/MaterialIcons-Regular.otf'))).load();
  });
  for (final setting in [
    (
      name: 'admin_login_light_desktop',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: false,
      overview: false,
    ),
    (
      name: 'admin_login_dark_desktop',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: true,
      overview: false,
    ),
    (
      name: 'admin_login_dark_mobile',
      size: const Size(390, 844),
      scale: 1.0,
      dark: true,
      overview: false,
    ),
    (
      name: 'admin_login_large_text_320',
      size: const Size(320, 844),
      scale: 2.0,
      dark: false,
      overview: false,
    ),
    (
      name: 'admin_overview_light_desktop',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: false,
      overview: true,
    ),
    (
      name: 'admin_overview_dark_desktop',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: true,
      overview: true,
    ),
    (
      name: 'admin_overview_mobile',
      size: const Size(390, 844),
      scale: 1.0,
      dark: false,
      overview: true,
    ),
    (
      name: 'admin_overview_large_text_320',
      size: const Size(320, 844),
      scale: 2.0,
      dark: false,
      overview: true,
    ),
  ]) {
    testWidgets('${setting.name}: labelled, scrollable, no overflow', (
      tester,
    ) async {
      tester.view.physicalSize = setting.size + const Offset(0, 32);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = setting.scale;
      tester.platformDispatcher.platformBrightnessTestValue = setting.dark
          ? Brightness.dark
          : Brightness.light;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            managementApiProvider.overrideWithValue(
              setting.overview ? OverviewFixture() : TestSession(),
            ),
          ],
          child: RepaintBoundary(
            key: const ValueKey('capture'),
            child: Directionality(
              textDirection: TextDirection.ltr,
              child: Column(
                children: [
                  Container(
                    height: 32,
                    color: const Color(0xFF273B32),
                    alignment: Alignment.center,
                    child: const Text(
                      '管理台设计预览 · 测试数据 · 非部署证明',
                      textScaler: TextScaler.noScaling,
                      style: TextStyle(
                        fontFamily: 'packages/vp_design_system/VpSans',
                        fontSize: 12,
                        color: Colors.white,
                      ),
                    ),
                  ),
                  const Expanded(child: VpAdminApp()),
                ],
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      if (!setting.overview) {
        expect(find.text('监听'), findsNothing);
        expect(find.text('欢迎回来'), findsOneWidget);
      }
      await expectLater(
        find.byKey(const ValueKey('capture')),
        matchesGoldenFile('goldens/${setting.name}.png'),
      );
      final reachable = setting.overview
          ? find.text('管理监听')
          : find.byKey(const ValueKey('management-login'));
      await tester.ensureVisible(reachable);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(reachable.hitTestable(), findsOneWidget);
      if (setting.overview) {
        expect(find.text('等待运行观测'), findsOneWidget);
        expect(find.text('运行修订一致'), findsNothing);
        await tester.ensureVisible(find.text('暂无操作记录'));
        await tester.pumpAndSettle();
        expect(find.text('暂无操作记录').hitTestable(), findsOneWidget);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }
}

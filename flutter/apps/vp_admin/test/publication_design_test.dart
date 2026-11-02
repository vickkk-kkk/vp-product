// Genuine Flutter widget previews with test-only metadata; not live deployment.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_admin/main.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';
import '../../../packages/vp_features/test/publication/fixtures.dart';

class AdminPublicationFixture extends PublicationFixtureApi {
  @override
  Future<ManagementSnapshot> snapshot() async => ManagementSnapshot(
    hostLabel: '独立服务器 · 组件预览',
    safeManagementOrigin: originLabel,
    revision: '3',
    observedRevision: '3',
    observedAt: DateTime.utc(2026, 10, 30, 12),
    listeners: const [],
    presets: const [],
    operations: const [],
    developmentBuild: true,
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
      name: 'publications_desktop',
      route: '/publications',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: false,
    ),
    (
      name: 'publications_dark',
      route: '/publications',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: true,
    ),
    (
      name: 'credentials_desktop',
      route: '/credentials',
      size: const Size(1440, 1000),
      scale: 1.0,
      dark: false,
    ),
    (
      name: 'node_wizard_desktop',
      route: '/listeners/new',
      size: const Size(1440, 1100),
      scale: 1.0,
      dark: false,
    ),
    (
      name: 'publications_large_type',
      route: '/publications',
      size: const Size(320, 844),
      scale: 2.0,
      dark: false,
    ),
    (
      name: 'wizard_mobile',
      route: '/listeners/new',
      size: const Size(390, 844),
      scale: 1.0,
      dark: false,
    ),
  ]) {
    testWidgets('${setting.name} no secret material and reachable controls', (
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
      final api = AdminPublicationFixture();
      await tester.pumpWidget(
        ProviderScope(
          overrides: [managementApiProvider.overrideWithValue(api)],
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
                      '管理台候选预览 · 测试数据 · 非实机部署',
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
      GoRouter.of(
        tester.element(find.byType(AdminOverviewPage)),
      ).go(setting.route);
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      expect(find.text(syntheticIssuedUrl), findsNothing);
      expect(find.textContaining('secret:fixture_reference'), findsNothing);
      await expectLater(
        find.byKey(const ValueKey('capture')),
        matchesGoldenFile('goldens/publication/${setting.name}.png'),
      );
      final action = setting.route == '/publications'
          ? find.text('签发访问链接')
          : setting.route == '/listeners/new'
          ? find.byKey(const ValueKey('generate-node-credential'))
          : find.text('回收未使用凭据');
      await tester.ensureVisible(action);
      await tester.pumpAndSettle();
      expect(action.hitTestable(), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }
}

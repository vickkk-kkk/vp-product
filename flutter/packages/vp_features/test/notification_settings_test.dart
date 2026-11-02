import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/src/providers.dart';
import 'package:vp_features/src/runtime_notification_settings.dart';
import 'fixtures/ports.dart';

class NotificationRuntime extends TestRuntime
    implements RuntimeNotificationControl {
  int requests = 0;
  bool granted = false;
  @override
  Future<RuntimeNotificationPermission> notificationPermission() async =>
      RuntimeNotificationPermission(granted: granted, canRequest: !granted);
  @override
  Future<RuntimeNotificationPermission> requestNotificationPermission() async {
    requests++;
    return notificationPermission();
  }
}

void main() {
  testWidgets(
    'notifications require explicit action and denial does not issue VPN command',
    (tester) async {
      final runtime = NotificationRuntime();
      await tester.pumpWidget(
        ProviderScope(
          overrides: [runtimeProvider.overrideWithValue(runtime)],
          child: MaterialApp(
            theme: VpTheme.build(Brightness.light),
            home: const Scaffold(body: RuntimeNotificationSettings()),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(runtime.requests, 0);
      expect(runtime.connects, 0);
      await tester.tap(find.byKey(const ValueKey('request-vpn-notifications')));
      await tester.pumpAndSettle();
      expect(runtime.requests, 1);
      expect(runtime.connects, 0);
      expect(find.textContaining('通知权限与 VPN 授权分开'), findsOneWidget);
      runtime.granted = true;
      await tester.tap(find.text('重新读取权限'));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('request-vpn-notifications')),
        findsNothing,
      );
      expect(runtime.requests, 1);
      await tester.pumpWidget(const SizedBox.shrink());
      await runtime.dispose();
    },
  );
}

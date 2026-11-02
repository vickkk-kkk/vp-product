import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_design_system/vp_design_system.dart';

void main() {
  testWidgets(
    '320 wide with 200 percent text and reduced motion shows complete error',
    (tester) async {
      tester.view.physicalSize = const Size(320, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(
        MaterialApp(
          theme: VpTheme.build(Brightness.light, highContrast: true),
          home: MediaQuery(
            data: const MediaQueryData(
              size: Size(320, 900),
              textScaler: TextScaler.linear(2),
              disableAnimations: true,
            ),
            child: const Scaffold(
              body: VpPage(
                eyebrow: '测试',
                title: '状态待刷新',
                description: '没有新的运行观测。',
                children: [
                  VpNotice(
                    title: '连接结果尚未确认',
                    message: '请查询原操作，不要重复提交。',
                    tone: VpTone.warning,
                  ),
                  VpLoading(label: '等待真实状态'),
                ],
              ),
            ),
          ),
        ),
      );
      expect(find.text('连接结果尚未确认'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );
  test('token values remain exact in both themes', () {
    expect(VpColors.light.canvas, const Color(0xFFF5F6F3));
    expect(VpColors.light.action, const Color(0xFF235B4B));
    expect(VpColors.dark.canvas, const Color(0xFF101714));
    expect(VpColors.dark.action, const Color(0xFF9BD4BC));
  });
}

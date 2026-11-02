import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_design_system/vp_design_system.dart';

void main() {
  testWidgets('connection control exposes an actionable accessible button', (
    tester,
  ) async {
    final handle = tester.ensureSemantics();

    var clicks = 0;
    await tester.pumpWidget(
      MaterialApp(
        theme: VpTheme.build(Brightness.light),
        home: Scaffold(
          body: Center(
            child: VpConnectionControl(label: '连接', onPressed: () => clicks++),
          ),
        ),
      ),
    );
    expect(
      tester.getSemantics(find.byType(VpConnectionControl)),
      matchesSemantics(
        label: '连接',
        isButton: true,
        hasEnabledState: true,
        isEnabled: true,
        hasTapAction: true,
      ),
    );
    await tester.tap(find.byType(VpConnectionControl));
    expect(clicks, 1);
    handle.dispose();
    await tester.pumpWidget(const SizedBox.shrink());
  });
  testWidgets(
    'unavailable action has no accessible tap and reduced motion does not spin',
    (tester) async {
      final handle = tester.ensureSemantics();

      await tester.pumpWidget(
        MaterialApp(
          theme: VpTheme.build(Brightness.dark),
          home: MediaQuery(
            data: const MediaQueryData(disableAnimations: true),
            child: Scaffold(
              body: Center(
                child: VpConnectionControl(
                  label: '连接',
                  onPressed: null,
                  busy: true,
                ),
              ),
            ),
          ),
        ),
      );
      expect(
        tester.getSemantics(find.byType(VpConnectionControl)),
        matchesSemantics(
          label: '连接',
          isButton: true,
          hasEnabledState: true,
          isEnabled: false,
          hasTapAction: false,
        ),
      );
      expect(find.byType(LinearProgressIndicator), findsNothing);
      expect(tester.takeException(), isNull);
      handle.dispose();
    },
  );
}

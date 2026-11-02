import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_design_system/vp_design_system.dart';

class MotionState {
  const MotionState({
    this.busy = false,
    this.verified = false,
    this.permission = false,
    this.attention = false,
    this.enabled = true,
  });
  final bool busy, verified, permission, attention, enabled;
}

Widget harness(
  ValueNotifier<MotionState> model,
  VoidCallback tap, {
  bool reduced = false,
}) => MaterialApp(
  theme: VpTheme.build(Brightness.light),
  home: MediaQuery(
    data: MediaQueryData(disableAnimations: reduced),
    child: Scaffold(
      body: Center(
        child: ValueListenableBuilder<MotionState>(
          valueListenable: model,
          builder: (context, state, _) => VpConnectionControl(
            label: state.permission
                ? '等待授权'
                : state.verified
                ? '断开连接'
                : state.busy
                ? '连接中'
                : '连接',
            onPressed: state.enabled ? tap : null,
            busy: state.busy,
            verified: state.verified,
            waitingForPermission: state.permission,
            attention: state.attention,
          ),
        ),
      ),
    ),
  ),
);
double scale(WidgetTester tester) => tester
    .widget<ScaleTransition>(
      find
          .descendant(
            of: find.byType(VpConnectionControl),
            matching: find.byType(ScaleTransition),
          )
          .first,
    )
    .scale
    .value;
void main() {
  testWidgets(
    'press has bounded depth, pointer cancellation releases without dispatch',
    (tester) async {
      final model = ValueNotifier(const MotionState());
      var taps = 0;
      await tester.pumpWidget(harness(model, () => taps++));
      await tester.pumpAndSettle();
      final gesture = await tester.startGesture(
        tester.getCenter(find.byType(VpConnectionControl)),
      );
      await tester.pump(const Duration(milliseconds: 120));
      await tester.pump(const Duration(milliseconds: 60));
      expect(scale(tester), inInclusiveRange(.964, .995));
      await gesture.cancel();
      await tester.pumpAndSettle();
      expect(scale(tester), closeTo(1, .001));
      expect(taps, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      model.dispose();
    },
  );
  testWidgets(
    'rapid click locks, permission stops orbit, real observed result owns success',
    (tester) async {
      final model = ValueNotifier(const MotionState());
      var taps = 0;
      await tester.pumpWidget(
        harness(model, () {
          taps++;
          model.value = const MotionState(busy: true, enabled: false);
        }),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byType(VpConnectionControl));
      await tester.pump();
      await tester.tap(find.byType(VpConnectionControl));
      await tester.pump(const Duration(seconds: 4));
      expect(taps, 1);
      expect(
        tester
            .widget<VpConnectionControl>(find.byType(VpConnectionControl))
            .verified,
        isFalse,
      );
      expect(tester.binding.hasScheduledFrame, isTrue);
      model.value = const MotionState(
        busy: true,
        permission: true,
        enabled: false,
      );
      await tester.pumpAndSettle();
      expect(tester.binding.hasScheduledFrame, isFalse);
      expect(find.text('等待授权'), findsOneWidget);
      model.value = const MotionState(verified: true);
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<VpConnectionControl>(find.byType(VpConnectionControl))
            .verified,
        isTrue,
      );
      expect(tester.binding.hasScheduledFrame, isFalse);
      await tester.pumpWidget(const SizedBox.shrink());
      model.dispose();
    },
  );
  testWidgets(
    'failure settles without shake and busy disposal leaves no ticker',
    (tester) async {
      final model = ValueNotifier(const MotionState(busy: true));
      await tester.pumpWidget(harness(model, () {}));
      await tester.pump(const Duration(milliseconds: 300));
      model.value = const MotionState(attention: true);
      await tester.pumpAndSettle();
      expect(scale(tester), 1);
      expect(tester.binding.hasScheduledFrame, isFalse);
      model.value = const MotionState(busy: true);
      await tester.pump(const Duration(milliseconds: 200));
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.pump(const Duration(seconds: 1));
      expect(tester.takeException(), isNull);
      model.dispose();
    },
  );
  testWidgets('reduced motion keeps press and pending ring stationary', (
    tester,
  ) async {
    final model = ValueNotifier(const MotionState());
    await tester.pumpWidget(
      harness(model, () {
        model.value = const MotionState(busy: true);
      }, reduced: true),
    );
    await tester.pumpAndSettle();
    final gesture = await tester.startGesture(
      tester.getCenter(find.byType(VpConnectionControl)),
    );
    await tester.pump(const Duration(milliseconds: 160));
    expect(scale(tester), 1);
    await gesture.up();
    await tester.pumpAndSettle();
    expect(tester.binding.hasScheduledFrame, isFalse);
    expect(scale(tester), 1);
    await tester.pumpWidget(const SizedBox.shrink());
    model.dispose();
  });
}

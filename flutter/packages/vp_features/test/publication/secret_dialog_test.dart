import 'dart:ui' show ViewFocusEvent, ViewFocusState, ViewFocusDirection;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/src/publication_secret_dialog.dart';
import 'fixtures.dart';

Future<void> openSecret(WidgetTester tester, PublicationFixtureApi api) async {
  await tester.pumpWidget(
    MaterialApp(
      theme: VpTheme.build(Brightness.light),
      home: Scaffold(
        body: Builder(
          builder: (context) => TextButton(
            onPressed: () =>
                showPublicationSecret(context, fixtureSecret(api.epoch), api),
            child: const Text('open'),
          ),
        ),
      ),
    ),
  );
  await tester.tap(find.text('open'));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets(
    'only explicit copy writes clipboard; close removes dedicated secret view',
    (tester) async {
      final api = PublicationFixtureApi();
      final clipboard = <String>[];
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        (call) async {
          if (call.method == 'Clipboard.setData')
            clipboard.add((call.arguments as Map)['text'] as String);
          return null;
        },
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          SystemChannels.platform,
          null,
        ),
      );
      await openSecret(tester, api);
      expect(clipboard, isEmpty);
      expect(find.text(syntheticIssuedUrl), findsOneWidget);
      expect(find.textContaining('手机不能'), findsOneWidget);
      expect(find.byKey(const ValueKey(syntheticIssuedUrl)), findsNothing);
      await tester.ensureVisible(
        find.byKey(const ValueKey('copy-subscription-link')),
      );
      await tester.tap(find.byKey(const ValueKey('copy-subscription-link')));
      await tester.pumpAndSettle();
      expect(clipboard, [syntheticIssuedUrl]);
      await tester.tap(find.text('关闭并清除展示'));
      await tester.pumpAndSettle();
      expect(find.text(syntheticIssuedUrl), findsNothing);
    },
  );
  testWidgets('focus loss clears, resuming never restores bearer display', (
    tester,
  ) async {
    final api = PublicationFixtureApi();
    await openSecret(tester, api);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pumpAndSettle();
    expect(find.text(syntheticIssuedUrl), findsNothing);
    expect(find.text('链接展示已清除'), findsOneWidget);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(find.text(syntheticIssuedUrl), findsNothing);
  });
  testWidgets(
    'session epoch invalidation clears active modal and copy control',
    (tester) async {
      final api = PublicationFixtureApi();
      await openSecret(tester, api);
      api.changeSession();
      await tester.pumpAndSettle();
      expect(find.text(syntheticIssuedUrl), findsNothing);
      expect(
        find.byKey(const ValueKey('copy-subscription-link')),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox.shrink());
      expect(api.listeners, isEmpty);
    },
  );
  testWidgets('platform view blur and covering route clear one-time display', (
    tester,
  ) async {
    final api = PublicationFixtureApi();
    await openSecret(tester, api);
    tester.binding.handleViewFocusChanged(
      ViewFocusEvent(
        viewId: tester.view.viewId,
        state: ViewFocusState.unfocused,
        direction: ViewFocusDirection.undefined,
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text(syntheticIssuedUrl), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    await openSecret(tester, api);
    final context = tester.element(find.text(syntheticIssuedUrl));
    final covered = Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => const Scaffold(body: Text('another route')),
      ),
    );
    await tester.pumpAndSettle();
    Navigator.of(tester.element(find.text('another route'))).pop();
    await covered;
    await tester.pumpAndSettle();
    expect(find.text(syntheticIssuedUrl), findsNothing);
  });
}

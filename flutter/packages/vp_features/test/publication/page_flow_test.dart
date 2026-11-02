import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/vp_features.dart';
import 'fixtures.dart';

Future<void> openPage(WidgetTester tester, PublicationFixtureApi api) async {
  tester.view.physicalSize = const Size(1200, 1200);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    ProviderScope(
      overrides: [managementApiProvider.overrideWithValue(api)],
      child: MaterialApp(
        theme: VpTheme.build(Brightness.light),
        home: const Scaffold(body: PublicationPage()),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> confirmIssue(WidgetTester tester) async {
  await tester.ensureVisible(find.text('签发访问链接'));
  await tester.tap(find.text('签发访问链接'));
  await tester.pumpAndSettle();
  await tester.tap(find.byType(CheckboxListTile));
  await tester.pump();
  await tester.tap(find.text('确认签发并仅展示一次'));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('page confirms issuance then shows only dedicated secret modal', (
    tester,
  ) async {
    final api = PublicationFixtureApi();
    await openPage(tester, api);
    expect(find.text(syntheticIssuedUrl), findsNothing);
    await confirmIssue(tester);
    expect(api.issueCommands, hasLength(1));
    expect(find.text(syntheticIssuedUrl), findsOneWidget);
    await tester.tap(find.text('关闭并清除展示'));
    await tester.pumpAndSettle();
    expect(find.text(syntheticIssuedUrl), findsNothing);
  });
  testWidgets(
    'navigation during token request never opens secret over the other route',
    (tester) async {
      final api = PublicationFixtureApi()..pendingIssue = Completer();
      await openPage(tester, api);
      await tester.ensureVisible(find.text('签发访问链接'));
      await tester.tap(find.text('签发访问链接'));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(CheckboxListTile));
      await tester.pump();
      await tester.tap(find.text('确认签发并仅展示一次'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      await tester.pump();
      expect(api.issueCommands, hasLength(1));
      final covered = Navigator.of(tester.element(find.byType(PublicationPage)))
          .push(
            MaterialPageRoute<void>(
              builder: (_) => const Scaffold(body: Text('different screen')),
            ),
          );
      await tester.pump(const Duration(milliseconds: 400));
      final result = fixtureSecret(api.epoch);
      api.pendingIssue!.complete(result);
      await tester.pumpAndSettle();
      expect(find.text(syntheticIssuedUrl), findsNothing);
      expect(result.isAvailable, isFalse);
      Navigator.of(tester.element(find.text('different screen'))).pop();
      await covered;
      await tester.pumpAndSettle();
      expect(find.text('链接可能已签发'), findsOneWidget);
      expect(find.text(syntheticIssuedUrl), findsNothing);
    },
  );
  testWidgets(
    'publication editor requires explicit endpoint and security mapping; creation does not issue token',
    (tester) async {
      final api = PublicationFixtureApi();
      await openPage(tester, api);
      await tester.tap(find.byKey(const ValueKey('create-publication')));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextFormField).first, '设备订阅');
      await tester.tap(find.widgetWithText(CheckboxListTile, '本机开发节点'));
      await tester.pumpAndSettle();
      final host = find.widgetWithText(TextFormField, '客户端连接主机');
      expect(tester.widget<TextFormField>(host).controller!.text, isEmpty);
      await tester.ensureVisible(host);
      await tester.enterText(host, '127.0.0.1');
      await tester.enterText(
        find.widgetWithText(TextFormField, '客户端连接端口'),
        '19090',
      );
      final mapConfirm = find.widgetWithText(
        CheckboxListTile,
        '我已核对这个节点的客户端连接地址和安全映射。',
      );
      await tester.ensureVisible(mapConfirm);
      await tester.tap(mapConfirm);
      await tester.pump();
      final publishConfirm = find.widgetWithText(
        CheckboxListTile,
        '我确认向持有订阅链接的人发布所选节点的连接凭据。',
      );
      await tester.ensureVisible(publishConfirm);
      await tester.tap(publishConfirm);
      await tester.pump();
      await tester.tap(find.text('创建发布内容'));
      await tester.pumpAndSettle();
      expect(api.creates, 1);
      expect(api.issueCommands, isEmpty);
      expect(find.text('创建发布内容'), findsNothing);
      expect(find.text(syntheticIssuedUrl), findsNothing);
    },
  );
}

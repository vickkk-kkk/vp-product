import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_features/vp_features.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'fixtures/ports.dart';

void main() {
  testWidgets(
    'source removal is typed, unchecked by default, and counted before commit',
    (tester) async {
      final preview = ImportPreview(
        id: 'preview',
        baseRevision: '1',
        items: const [
          ImportItem(
            id: 'incoming',
            safeName: 'Incoming',
            status: ImportItemStatus.ready,
            explanation: 'Adds node',
          ),
          ImportItem(
            id: 'removed',
            safeName: 'Removed source node',
            status: ImportItemStatus.ready,
            action: ImportAction.remove,
            explanation: 'Deletes only if explicitly selected',
          ),
        ],
        warnings: const [],
        expiresAt: DateTime.now().add(const Duration(minutes: 10)),
        isNodeExtraction: false,
        requiresExplicitNodeExtraction: false,
      );
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            repositoryProvider.overrideWithValue(TestRepository()),
            importServiceProvider.overrideWithValue(TestImporter()),
          ],
          child: MaterialApp(
            theme: VpTheme.build(Brightness.light),
            home: ImportPage(initialPreview: preview),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final tiles = tester
          .widgetList<CheckboxListTile>(find.byType(CheckboxListTile))
          .toList();
      expect(tiles[0].value, true);
      expect(tiles[1].value, false);
      expect(find.text('应用选中 1 项（删除 0 项）'), findsOneWidget);
      await tester.ensureVisible(find.text('Removed source node'));
      await tester.tap(find.text('Removed source node'));
      await tester.pump();
      expect(find.text('应用选中 2 项（删除 1 项）'), findsOneWidget);
      expect(find.textContaining('删除 · 可导入'), findsOneWidget);
    },
  );
}

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/src/client_pages.dart';
import 'package:vp_features/src/providers.dart';
import 'fixtures/ports.dart';

class RefreshRepository extends TestRepository
    implements SubscriptionRefreshLifecycle, ImportPreviewLifecycle {
  final result = Completer<ImportPreview>();
  final cancelled = <String>[];
  final discarded = <String>[];
  int previews = 0;
  RefreshRepository() {
    current = Revisioned(
      revision: 'opaque',
      observedAt: DateTime.now(),
      value: const ClientInventory(
        nodes: [],
        subscriptions: [
          SubscriptionView(
            id: 'source:test',
            name: 'Synthetic source',
            safeOrigin: 'https://example.invalid',
            nodeCount: 0,
          ),
        ],
      ),
    );
  }
  @override
  Future<ImportPreview> previewSubscriptionRefresh(String sourceId) {
    previews++;
    return result.future;
  }

  @override
  void cancelSubscriptionRefresh(String sourceId) => cancelled.add(sourceId);
  @override
  void discardPreview(String previewId) => discarded.add(previewId);
}

void main() {
  testWidgets(
    'leaving refresh cancels request and disposes a late native preview',
    (tester) async {
      final repository = RefreshRepository();
      await tester.pumpWidget(
        ProviderScope(
          overrides: [repositoryProvider.overrideWithValue(repository)],
          child: MaterialApp(
            theme: VpTheme.build(Brightness.light),
            home: const Scaffold(body: SubscriptionPage()),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('预览更新'));
      await tester.tap(find.text('预览更新'));
      await tester.pump();
      expect(repository.previews, 1);
      await tester.pumpWidget(const SizedBox.shrink());
      expect(repository.cancelled, ['source:test']);
      repository.result.complete(preview());
      await tester.pumpAndSettle();
      expect(repository.discarded, ['preview:test']);
      expect(tester.takeException(), isNull);
    },
  );
}

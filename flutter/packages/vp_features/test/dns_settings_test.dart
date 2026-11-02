import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_features/src/providers.dart';
import 'package:vp_features/src/user_dns_settings.dart';
import 'fixtures/ports.dart';

class DnsRepository extends TestRepository
    implements ClientDnsSettingsRepository {
  final saved = <UserDnsSettings?>[];
  Object? saveError;
  @override
  Future<MutationReceipt> saveUserDns(
    UserDnsSettings? settings,
    MutationIdentity command,
  ) async {
    mutations++;
    lastCommand = command;
    saved.add(settings);
    if (saveError != null) throw saveError!;
    final receipt =
        await (pending?.future ??
            Future.value(
              const MutationReceipt(operationId: 'dns:test', revision: 'next'),
            ));
    current = Revisioned(
      revision: receipt.revision,
      observedAt: DateTime.now(),
      value: ClientInventory(
        nodes: const [],
        subscriptions: const [],
        userDns: settings,
      ),
    );
    return receipt;
  }
}

Widget app(TestRepository repository) => ProviderScope(
  overrides: [repositoryProvider.overrideWithValue(repository)],
  child: MaterialApp(
    theme: VpTheme.build(Brightness.light),
    home: const Scaffold(
      body: SingleChildScrollView(child: UserDnsSettingsEditor()),
    ),
  ),
);

void main() {
  testWidgets(
    '320px and 200 percent text retain editable endpoints and no layout overflow',
    (tester) async {
      tester.view.physicalSize = const Size(320, 800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final repository = DnsRepository();
      await tester.pumpWidget(
        ProviderScope(
          overrides: [repositoryProvider.overrideWithValue(repository)],
          child: MaterialApp(
            theme: VpTheme.build(Brightness.light),
            builder: (context, child) => MediaQuery(
              data: MediaQuery.of(
                context,
              ).copyWith(textScaler: const TextScaler.linear(2)),
              child: child!,
            ),
            home: const Scaffold(
              body: SingleChildScrollView(child: UserDnsSettingsEditor()),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const ValueKey('user-dns-servers')),
        '[fd89:7670::2]:5353',
      );
      await tester.pump();
      await tester.ensureVisible(find.byKey(const ValueKey('save-user-dns')));
      expect(tester.takeException(), isNull);
      expect(
        tester
            .widget<TextField>(find.byKey(const ValueKey('user-dns-servers')))
            .controller!
            .text,
        '[fd89:7670::2]:5353',
      );
    },
  );
  testWidgets(
    'unset DNS stays blank; explicit save uses opaque inventory identity and no duplicate submission',
    (tester) async {
      final repository = DnsRepository()
        ..current = inventory(revision: 'opaque-inventory')
        ..pending = Completer<MutationReceipt>();
      await tester.pumpWidget(app(repository));
      await tester.pumpAndSettle();
      expect(find.text('尚未设置；连接前需要填写。'), findsOneWidget);
      final field = tester.widget<TextField>(
        find.byKey(const ValueKey('user-dns-servers')),
      );
      expect(field.controller!.text, '');
      await tester.enterText(
        find.byKey(const ValueKey('user-dns-servers')),
        ' 10.0.2.2:5353\n[fd89:7670::2]:5353 ',
      );
      await tester.pump();
      await tester.tap(find.byKey(const ValueKey('save-user-dns')));
      await tester.pump();
      await tester.pump();
      await tester.tap(find.byKey(const ValueKey('save-user-dns')));
      expect(repository.mutations, 1);
      expect(repository.lastCommand!.expectedRevision, 'opaque-inventory');
      expect(repository.saved.single!.servers, [
        '10.0.2.2:5353',
        '[fd89:7670::2]:5353',
      ]);
      expect(repository.saved.single!.route, 'selected_proxy');
      repository.pending!.complete(
        const MutationReceipt(operationId: 'dns:test', revision: 'next'),
      );
      await tester.pumpAndSettle();
      expect(find.text('已保存 2 个服务器。'), findsOneWidget);
    },
  );

  testWidgets(
    'uncertain save preserves input and prohibits new command until reconciliation',
    (tester) async {
      final repository = DnsRepository()
        ..saveError = const ProductFailure(
          'STORAGE_SYNC_FAILED',
          'Test unknown result',
          outcomeUnknown: true,
        );
      await tester.pumpWidget(app(repository));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const ValueKey('user-dns-servers')),
        '10.0.2.2:5353',
      );
      await tester.pump();
      await tester.tap(find.byKey(const ValueKey('save-user-dns')));
      await tester.pumpAndSettle();
      expect(repository.mutations, 1);
      expect(
        tester
            .widget<FilledButton>(find.byKey(const ValueKey('save-user-dns')))
            .onPressed,
        isNull,
      );
      expect(
        tester
            .widget<TextField>(find.byKey(const ValueKey('user-dns-servers')))
            .controller!
            .text,
        '10.0.2.2:5353',
      );
      final identity = repository.lastCommand;
      await tester.pumpAndSettle();
      expect(repository.lastCommand, same(identity));
    },
  );

  testWidgets(
    'clear requires confirmation and sends null rather than fallback DNS',
    (tester) async {
      final repository = DnsRepository()
        ..current = Revisioned(
          revision: 'configured',
          observedAt: DateTime.now(),
          value: ClientInventory(
            nodes: const [],
            subscriptions: const [],
            userDns: UserDnsSettings(servers: ['10.0.2.2:5353']),
          ),
        );
      await tester.pumpWidget(app(repository));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('clear-user-dns')));
      await tester.pumpAndSettle();
      expect(repository.mutations, 0);
      await tester.tap(find.text('取消'));
      await tester.pumpAndSettle();
      expect(repository.mutations, 0);
      await tester.tap(find.byKey(const ValueKey('clear-user-dns')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('确认清除'));
      await tester.pumpAndSettle();
      expect(repository.saved, [null]);
      expect(find.text('尚未设置；连接前需要填写。'), findsOneWidget);
    },
  );

  testWidgets('unsupported repository has no pretend DNS controls', (
    tester,
  ) async {
    await tester.pumpWidget(app(TestRepository()));
    await tester.pumpAndSettle();
    expect(find.text('此平台暂不支持配置'), findsOneWidget);
    expect(find.byKey(const ValueKey('save-user-dns')), findsNothing);
  });
}

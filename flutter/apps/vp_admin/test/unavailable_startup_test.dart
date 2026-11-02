import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vp_admin/main.dart';

void main() {
  testWidgets(
    'admin startup never invents authenticated host or healthy listeners',
    (tester) async {
      await tester.pumpWidget(const ProviderScope(child: VpAdminApp()));
      await tester.pumpAndSettle();
      expect(find.text('当前无法登录'), findsOneWidget);
      expect(find.text('尚未识别服务器'), findsNothing);
      expect(find.text('监听'), findsNothing);
      expect(find.text('数据服务健康'), findsNothing);
    },
  );
}

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_features/vp_features.dart';

void main() => runApp(
  ProviderScope(
    overrides: [
      managementApiProvider.overrideWith((ref) {
        final api = createManagementApi();
        ref.onDispose(api.close);
        return api;
      }),
    ],
    child: const VpAdminApp(),
  ),
);

class VpAdminApp extends StatefulWidget {
  const VpAdminApp({super.key});
  @override
  State<VpAdminApp> createState() => _VpAdminAppState();
}

class _VpAdminAppState extends State<VpAdminApp> {
  late final router = GoRouter(
    initialLocation: '/overview',
    routes: [
      GoRoute(
        path: '/login',
        builder: (_, state) => const ManagementLoginPage(),
      ),
      ShellRoute(
        builder: (context, state, child) =>
            _AdminAccessGate(path: state.uri.path, child: child),
        routes: [
          GoRoute(
            path: '/overview',
            builder: (_, state) => const AdminOverviewPage(),
          ),
          GoRoute(
            path: '/listeners/new',
            builder: (_, state) => const NewUuidListenerPage(),
          ),
          GoRoute(
            path: '/publications',
            builder: (_, state) => const PublicationPage(),
          ),
          GoRoute(
            path: '/listeners',
            builder: (_, state) => const ListenerPage(),
          ),
          GoRoute(
            path: '/credentials',
            builder: (_, state) => const ManagementCredentialsPage(),
          ),
          GoRoute(
            path: '/routing',
            builder: (_, state) => const PendingFeaturePage(
              title: '路由与 DNS',
              description: '规则顺序与解析策略的改变必须通过校验、差异预览与实际修订验证。',
            ),
          ),
          GoRoute(
            path: '/diagnostics',
            builder: (_, state) => const DiagnosticsPage(admin: true),
          ),
          GoRoute(
            path: '/maintenance',
            builder: (_, state) => const MaintenancePage(),
            routes: [
              GoRoute(
                path: 'plan',
                builder: (_, state) => const PlanReviewPage(),
              ),
              GoRoute(
                path: 'operations/:id',
                builder: (_, state) =>
                    OperationPage(operationId: state.pathParameters['id']!),
              ),
            ],
          ),
        ],
      ),
    ],
  );
  @override
  void dispose() {
    router.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => MaterialApp.router(
    title: 'VP · 服务器管理',
    debugShowCheckedModeBanner: false,
    routerConfig: router,
    theme: VpTheme.build(Brightness.light),
    darkTheme: VpTheme.build(Brightness.dark),
    highContrastTheme: VpTheme.build(Brightness.light, highContrast: true),
    highContrastDarkTheme: VpTheme.build(Brightness.dark, highContrast: true),
    themeMode: ThemeMode.system,
  );
}

/// The API snapshot restores a cookie session before any business navigation is
/// rendered. A readable page is never treated as authenticated server access.
class _AdminAccessGate extends ConsumerWidget {
  const _AdminAccessGate({required this.path, required this.child});
  final String path;
  final Widget child;
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        if (ref.read(managementSessionProvider).authenticated) {
          return VpShell(admin: true, path: path, child: child);
        }
        if (controller.state is Loading) {
          return const Scaffold(
            body: Center(
              child: SizedBox(width: 240, child: VpLoading(label: '正在确认管理会话…')),
            ),
          );
        }
        return ManagementLoginPage(returnPath: path);
      },
    );
  }
}

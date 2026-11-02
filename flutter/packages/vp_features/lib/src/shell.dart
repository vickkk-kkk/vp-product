import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_design_system/vp_design_system.dart';

class VpDestination {
  const VpDestination(this.path, this.label, this.icon);
  final String path, label;
  final IconData icon;
}

const clientDestinations = [
  VpDestination('/connection', '连接', Icons.shield_outlined),
  VpDestination('/nodes', '节点', Icons.dns_outlined),
  VpDestination('/subscriptions', '订阅', Icons.subscriptions_outlined),
  VpDestination('/settings', '设置', Icons.tune),
];
const adminDestinations = [
  VpDestination('/overview', '概览', Icons.space_dashboard_outlined),
  VpDestination('/listeners', '监听', Icons.dns_outlined),
  VpDestination('/credentials', '连接凭据', Icons.key_outlined),
  VpDestination('/publications', '订阅发布', Icons.rss_feed),
  VpDestination('/routing', '路由与 DNS', Icons.alt_route),
  VpDestination('/diagnostics', '诊断', Icons.fact_check_outlined),
  VpDestination('/maintenance', '维护', Icons.build_outlined),
];

class VpShell extends StatelessWidget {
  const VpShell({
    super.key,
    required this.child,
    required this.path,
    this.admin = false,
  });
  final Widget child;
  final String path;
  final bool admin;
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, box) {
      if (admin) return _AdminWorkspace(path: path, child: child);
      final destinations = admin ? adminDestinations : clientDestinations;
      var selected = destinations.indexWhere(
        (item) => path.startsWith(item.path),
      );
      if (selected < 0)
        selected = admin
            ? 0
            : path.startsWith('/import')
            ? 1
            : 3;
      final wide = box.maxWidth >= 600;
      final extended = box.maxWidth >= 960;
      final title = admin ? '服务器管理' : '本机连接';
      void navigate(int index) => context.go(destinations[index].path);
      final colors = VpColors.of(context);
      final dark = Theme.of(context).brightness == Brightness.dark;
      final systemStyle = SystemUiOverlayStyle(
        statusBarColor: colors.canvas,
        statusBarIconBrightness: dark ? Brightness.light : Brightness.dark,
        statusBarBrightness: dark ? Brightness.dark : Brightness.light,
        systemNavigationBarColor: colors.canvas,
        systemNavigationBarIconBrightness: dark
            ? Brightness.light
            : Brightness.dark,
        systemNavigationBarDividerColor: colors.canvas,
        systemNavigationBarContrastEnforced: false,
        systemStatusBarContrastEnforced: false,
      );
      return AnnotatedRegion<SystemUiOverlayStyle>(
        value: systemStyle,
        child: Scaffold(
          appBar: !wide
              ? AppBar(
                  systemOverlayStyle: systemStyle,
                  toolbarHeight: admin ? 56 : 64,
                  titleSpacing: admin ? null : 24,
                  title: admin
                      ? Text('VP · $title')
                      : Text(
                          'VP',
                          style: Theme.of(context).textTheme.headlineMedium
                              ?.copyWith(letterSpacing: -.8),
                        ),
                  actions: !admin
                      ? [
                          IconButton(
                            tooltip: '导入节点',
                            onPressed: () => context.push('/import'),
                            icon: const Icon(Icons.add),
                          ),
                        ]
                      : null,
                )
              : null,
          drawer: admin && !wide
              ? Drawer(
                  child: SafeArea(
                    child: Column(
                      children: [
                        const ListTile(
                          title: Text('VP · 服务器管理'),
                          subtitle: Text('浏览器不会接管本机网络'),
                        ),
                        for (
                          var index = 0;
                          index < destinations.length;
                          index++
                        )
                          ListTile(
                            selected: index == selected,
                            leading: Icon(destinations[index].icon),
                            title: Text(destinations[index].label),
                            onTap: () {
                              Navigator.pop(context);
                              navigate(index);
                            },
                          ),
                      ],
                    ),
                  ),
                )
              : null,
          bottomNavigationBar: !admin && !wide
              ? _ClientNavigation(selected: selected, onSelect: navigate)
              : null,
          body: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (wide) ...[
                NavigationRail(
                  extended: extended,
                  minWidth: 80,
                  minExtendedWidth: box.maxWidth >= 1280 ? 232 : 216,
                  selectedIndex: selected,
                  onDestinationSelected: navigate,
                  labelType: extended
                      ? NavigationRailLabelType.none
                      : NavigationRailLabelType.all,
                  leading: Padding(
                    padding: const EdgeInsets.symmetric(
                      vertical: 24,
                      horizontal: 8,
                    ),
                    child: extended
                        ? Text(
                            'VP  /  $title',
                            style: Theme.of(context).textTheme.titleLarge,
                          )
                        : Semantics(
                            label: 'VP · $title',
                            child: const Text('VP'),
                          ),
                  ),
                  destinations: [
                    for (final item in destinations)
                      NavigationRailDestination(
                        icon: Icon(item.icon),
                        label: Text(item.label),
                      ),
                  ],
                ),
                VerticalDivider(
                  width: 1,
                  color: VpColors.of(context).borderSubtle,
                ),
              ],
              Expanded(child: child),
            ],
          ),
        ),
      );
    },
  );
}

class _ClientNavigation extends StatelessWidget {
  const _ClientNavigation({required this.selected, required this.onSelect});
  final int selected;
  final ValueChanged<int> onSelect;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    return ColoredBox(
      color: c.canvas,
      child: SafeArea(
        top: false,
        minimum: const EdgeInsets.only(bottom: 8),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: Row(
            children: [
              for (var i = 0; i < clientDestinations.length; i++)
                Expanded(
                  child: Semantics(
                    selected: selected == i,
                    button: true,
                    label: clientDestinations[i].label,
                    onTap: () => onSelect(i),
                    child: ExcludeSemantics(
                      child: InkWell(
                        onTap: () => onSelect(i),
                        borderRadius: BorderRadius.circular(16),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 10),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                clientDestinations[i].icon,
                                size: 23,
                                color: selected == i
                                    ? c.action
                                    : c.textTertiary,
                              ),
                              const SizedBox(height: 5),
                              Text(
                                clientDestinations[i].label,
                                style: Theme.of(context).textTheme.labelMedium
                                    ?.copyWith(
                                      color: selected == i
                                          ? c.action
                                          : c.textSecondary,
                                    ),
                              ),
                              const SizedBox(height: 6),
                              Container(
                                width: 14,
                                height: 2,
                                decoration: BoxDecoration(
                                  color: selected == i
                                      ? c.action
                                      : Colors.transparent,
                                  borderRadius: BorderRadius.circular(2),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Desktop management is a workspace, not an expanded phone navigation bar.
class _AdminWorkspace extends StatelessWidget {
  const _AdminWorkspace({required this.path, required this.child});
  final String path;
  final Widget child;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final t = Theme.of(context).textTheme;
    final selected = adminDestinations.indexWhere(
      (item) => path.startsWith(item.path),
    );
    final title = selected < 0 ? '服务器管理' : adminDestinations[selected].label;
    Widget navigation({bool drawer = false}) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Row(
                children: [
                  Text(
                    'VP',
                    style: t.headlineMedium?.copyWith(letterSpacing: -1),
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text('服务器管理', style: t.labelLarge)),
                ],
              ),
            ),
            const SizedBox(height: 48),
            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  children: [
                    for (var i = 0; i < adminDestinations.length; i++) ...[
                      if (adminDestinations[i].path == '/diagnostics')
                        const Padding(
                          padding: EdgeInsets.symmetric(vertical: 20),
                          child: Divider(height: 1),
                        ),
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: ListTile(
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                          ),
                          selected: selected == i,
                          selectedTileColor: c.selectedSurface,
                          selectedColor: c.action,
                          contentPadding: const EdgeInsets.symmetric(
                            horizontal: 12,
                          ),
                          horizontalTitleGap: 12,
                          leading: SizedBox(
                            width: 32,
                            child: Row(
                              children: [
                                Container(
                                  width: 3,
                                  height: 20,
                                  decoration: BoxDecoration(
                                    color: selected == i
                                        ? c.action
                                        : Colors.transparent,
                                    borderRadius: BorderRadius.circular(2),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Icon(adminDestinations[i].icon, size: 21),
                              ],
                            ),
                          ),
                          title: Text(
                            adminDestinations[i].label,
                            style: t.labelLarge,
                          ),
                          onTap: () {
                            if (drawer) Navigator.pop(context);
                            context.go(adminDestinations[i].path);
                          },
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const Divider(),
            const SizedBox(height: 12),
            TextButton.icon(
              onPressed: () {
                if (drawer) Navigator.pop(context);
                context.go('/login');
              },
              icon: const Icon(Icons.account_circle_outlined, size: 20),
              label: const Text('管理会话'),
            ),
            const SizedBox(height: 16),
            Text(
              '远端管理 · 不接管本机网络',
              textAlign: TextAlign.center,
              style: t.labelSmall?.copyWith(color: c.textSecondary),
            ),
          ],
        ),
      ),
    );
    return LayoutBuilder(
      builder: (context, box) {
        final desktop =
            box.maxWidth >= 1000 &&
            MediaQuery.textScalerOf(context).scale(1) < 1.6;
        return Scaffold(
          appBar: desktop ? null : AppBar(title: Text(title)),
          drawer: desktop ? null : Drawer(child: navigation(drawer: true)),
          body: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (desktop) ...[
                SizedBox(
                  width: 232,
                  child: Material(color: c.surface, child: navigation()),
                ),
                VerticalDivider(width: 1, color: c.borderSubtle),
              ],
              Expanded(
                child: Column(
                  children: [
                    if (desktop)
                      Container(
                        height: 72,
                        padding: const EdgeInsets.symmetric(horizontal: 40),
                        decoration: BoxDecoration(
                          border: Border(
                            bottom: BorderSide(color: c.borderSubtle),
                          ),
                        ),
                        child: Row(
                          children: [
                            Text(
                              '工作空间',
                              style: t.bodySmall?.copyWith(
                                color: c.textSecondary,
                              ),
                            ),
                            Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 14,
                              ),
                              child: Text(
                                '/',
                                style: t.bodySmall?.copyWith(
                                  color: c.textTertiary,
                                ),
                              ),
                            ),
                            Text(title, style: t.labelLarge),
                            const Spacer(),
                            Icon(
                              Icons.dns_outlined,
                              size: 18,
                              color: c.textSecondary,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              '独立服务器',
                              style: t.bodySmall?.copyWith(
                                color: c.textSecondary,
                              ),
                            ),
                          ],
                        ),
                      ),
                    Expanded(child: child),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

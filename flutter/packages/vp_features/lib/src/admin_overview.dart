import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'providers.dart';
import 'state.dart';

class AdminOverviewPage extends ConsumerWidget {
  const AdminOverviewPage({super.key});
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final snapshot = controller.state.previous;
        final c = VpColors.of(context);
        final t = Theme.of(context).textTheme;
        return LayoutBuilder(
          builder: (context, box) {
            final roomy =
                box.maxWidth >= 900 &&
                MediaQuery.textScalerOf(context).scale(1) < 1.6;
            final margin = box.maxWidth < 600 ? 24.0 : 40.0;
            Widget columns(Widget primary, Widget secondary) => roomy
                ? Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(flex: 7, child: primary),
                      const SizedBox(width: 24),
                      Expanded(flex: 4, child: secondary),
                    ],
                  )
                : Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [primary, const SizedBox(height: 24), secondary],
                  );
            return SafeArea(
              child: SingleChildScrollView(
                padding: EdgeInsets.all(margin),
                child: Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 1320),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Text(
                          '服务器概览',
                          style: t.labelLarge?.copyWith(color: c.textSecondary),
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          alignment: WrapAlignment.spaceBetween,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          spacing: 24,
                          runSpacing: 16,
                          children: [
                            ConstrainedBox(
                              constraints: BoxConstraints(
                                maxWidth: (box.maxWidth - margin * 2).clamp(
                                  0,
                                  700,
                                ),
                              ),
                              child: Text(
                                snapshot?.hostLabel ?? '尚未识别服务器',
                                style: t.headlineLarge?.copyWith(
                                  fontSize: 32,
                                  letterSpacing: -.7,
                                ),
                              ),
                            ),
                            OutlinedButton.icon(
                              onPressed: controller.state is Loading
                                  ? null
                                  : controller.refresh,
                              icon: const Icon(Icons.refresh, size: 18),
                              label: const Text('刷新状态'),
                            ),
                          ],
                        ),
                        if (snapshot != null) ...[
                          const SizedBox(height: 12),
                          Wrap(
                            spacing: 20,
                            runSpacing: 8,
                            children: [
                              Text(
                                safeOrigin(snapshot.safeManagementOrigin),
                                style: t.bodyMedium?.copyWith(
                                  color: c.textSecondary,
                                ),
                              ),
                              Text(
                                '读取于 ${formatMoment(snapshot.observedAt)}',
                                style: t.bodySmall?.copyWith(
                                  color: c.textTertiary,
                                ),
                              ),
                            ],
                          ),
                        ],
                        if (controller.state is! Loaded) ...[
                          const SizedBox(height: 24),
                          LoadNotice(
                            controller.state,
                            retry: controller.refresh,
                          ),
                        ],
                        if (controller.mutation is! MutationIdle) ...[
                          const SizedBox(height: 24),
                          MutationNotice(
                            controller.mutation,
                            onReconcile: controller.reconcile,
                          ),
                        ],
                        const SizedBox(height: 32),
                        if (snapshot?.developmentBuild == true) ...[
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 16,
                              vertical: 13,
                            ),
                            decoration: BoxDecoration(
                              color: c.warningSurface,
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Icon(
                                  Icons.science_outlined,
                                  size: 20,
                                  color: c.warning,
                                ),
                                const SizedBox(width: 12),
                                Expanded(
                                  child: Text(
                                    '开发构建 · 运行能力尚未完成产品认证',
                                    style: t.bodySmall?.copyWith(
                                      color: c.warning,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 24),
                        ],
                        if (snapshot != null) ...[
                          columns(
                            _RuntimePanel(snapshot: snapshot),
                            _OverviewPanel(
                              title: '配置变更',
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                                  Text('先预览，再应用。', style: t.titleLarge),
                                  const SizedBox(height: 12),
                                  Text(
                                    '查看监听与协议支持范围。每次修改都需要校验和确认变更计划。',
                                    style: t.bodyMedium?.copyWith(
                                      color: c.textSecondary,
                                    ),
                                  ),
                                  const SizedBox(height: 28),
                                  FilledButton.icon(
                                    onPressed: () => context.go('/listeners'),
                                    icon: const Icon(Icons.tune, size: 18),
                                    label: const Text('管理监听'),
                                  ),
                                  const SizedBox(height: 8),
                                  TextButton(
                                    onPressed: () => context.go('/maintenance'),
                                    child: const Text('维护与操作记录'),
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(height: 24),
                          columns(
                            _OverviewPanel(
                              title: '监听',
                              trailing: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    '${snapshot.listeners.length} 项',
                                    style: t.labelLarge?.copyWith(
                                      color: c.textSecondary,
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  IconButton(
                                    tooltip: '查看全部监听',
                                    onPressed: () => context.go('/listeners'),
                                    icon: const Icon(
                                      Icons.arrow_forward,
                                      size: 18,
                                    ),
                                  ),
                                ],
                              ),
                              child: snapshot.listeners.isEmpty
                                  ? _QuietEmpty(
                                      icon: Icons.dns_outlined,
                                      title: '还没有监听',
                                      message: '先选择协议模板，确认此服务器支持的能力。',
                                      action: TextButton(
                                        onPressed: () =>
                                            context.go('/listeners'),
                                        child: const Text('查看协议模板 →'),
                                      ),
                                    )
                                  : Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.stretch,
                                      children: [
                                        for (final listener
                                            in snapshot.listeners.take(5))
                                          _ListenerSummary(listener: listener),
                                      ],
                                    ),
                            ),
                            _OverviewPanel(
                              title: '操作记录',
                              child: snapshot.operations.isEmpty
                                  ? const _QuietEmpty(
                                      icon: Icons.history,
                                      title: '暂无操作记录',
                                      message: '应用配置后，可在这里追踪执行结果。',
                                    )
                                  : Column(
                                      children: [
                                        for (final operation
                                            in snapshot.operations.take(4))
                                          ListTile(
                                            contentPadding: EdgeInsets.zero,
                                            title: Text(operation.stage),
                                            subtitle: Text(
                                              operation.lastMessage,
                                            ),
                                            trailing: const Icon(
                                              Icons.chevron_right,
                                              size: 18,
                                            ),
                                            onTap: () => context.go(
                                              '/maintenance/operations/${Uri.encodeComponent(operation.id)}',
                                            ),
                                          ),
                                      ],
                                    ),
                            ),
                          ),
                          const SizedBox(height: 28),
                          Text(
                            '管理会话与节点连接凭据相互独立。运行情况以服务器实际观测为准。',
                            style: t.bodySmall?.copyWith(color: c.textTertiary),
                          ),
                        ],
                        const SizedBox(height: 24),
                      ],
                    ),
                  ),
                ),
              ),
            );
          },
        );
      },
    );
  }
}

class _RuntimePanel extends StatelessWidget {
  const _RuntimePanel({required this.snapshot});
  final ManagementSnapshot snapshot;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final t = Theme.of(context).textTheme;
    final observed = snapshot.observedRevision;
    final aligned = observed != null && observed == snapshot.revision;
    return _OverviewPanel(
      title: '运行状态',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: c.surfaceSubtle,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  observed == null
                      ? Icons.pending_outlined
                      : Icons.layers_outlined,
                  color: c.action,
                  size: 24,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      observed == null
                          ? '等待运行观测'
                          : aligned
                          ? '运行修订一致'
                          : '运行修订待同步',
                      style: t.titleLarge,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      observed == null
                          ? '还没有实际运行结果，不能确认数据服务已生效。'
                          : aligned
                          ? '当前观测与期望配置一致。各监听状态见下方。'
                          : '期望配置与实际运行修订不同，请查看操作结果。',
                      style: t.bodyMedium?.copyWith(color: c.textSecondary),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 28),
          const Divider(height: 1),
          const SizedBox(height: 24),
          LayoutBuilder(
            builder: (context, box) {
              Widget value(String label, String value) => Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: t.bodySmall?.copyWith(color: c.textSecondary),
                  ),
                  const SizedBox(height: 8),
                  Text(value, style: t.headlineSmall),
                ],
              );
              return box.maxWidth < 360 ||
                      MediaQuery.textScalerOf(context).scale(1) > 1.5
                  ? Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        value('期望配置修订', snapshot.revision),
                        const SizedBox(height: 20),
                        value('实际运行修订', observed ?? '尚未观测'),
                      ],
                    )
                  : Row(
                      children: [
                        Expanded(child: value('期望配置修订', snapshot.revision)),
                        Expanded(child: value('实际运行修订', observed ?? '尚未观测')),
                      ],
                    );
            },
          ),
        ],
      ),
    );
  }
}

class _OverviewPanel extends StatelessWidget {
  const _OverviewPanel({
    required this.title,
    required this.child,
    this.trailing,
  });
  final String title;
  final Widget child;
  final Widget? trailing;
  @override
  Widget build(BuildContext context) => VpPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                title,
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  color: VpColors.of(context).textSecondary,
                ),
              ),
            ),
            if (trailing != null) trailing!,
          ],
        ),
        const SizedBox(height: 24),
        child,
      ],
    ),
  );
}

class _QuietEmpty extends StatelessWidget {
  const _QuietEmpty({
    required this.icon,
    required this.title,
    required this.message,
    this.action,
  });
  final IconData icon;
  final String title, message;
  final Widget? action;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 16),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 28, color: VpColors.of(context).textTertiary),
        const SizedBox(height: 20),
        Text(title, style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Text(
          message,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
            color: VpColors.of(context).textSecondary,
          ),
        ),
        if (action != null) ...[const SizedBox(height: 16), action!],
      ],
    ),
  );
}

class _ListenerSummary extends StatelessWidget {
  const _ListenerSummary({required this.listener});
  final ListenerView listener;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 20),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 16,
          runSpacing: 8,
          children: [
            Text(listener.name, style: Theme.of(context).textTheme.titleMedium),
            Text(
              listener.observedState,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: VpColors.of(context).textSecondary,
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          '${listener.bind}:${listener.port} · ${listener.presetKey}',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        if (listener.problem != null) ...[
          const SizedBox(height: 8),
          Text(
            listener.problem!.message,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: VpColors.of(context).warning,
            ),
          ),
        ],
      ],
    ),
  );
}

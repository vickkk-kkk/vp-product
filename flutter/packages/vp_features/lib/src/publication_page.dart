import 'dart:ui' show ViewFocusEvent, ViewFocusState;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'publication_controller.dart';
import 'publication_secret_dialog.dart';
import 'publication_editor.dart';
import 'providers.dart';
import 'state.dart';

class PublicationPage extends ConsumerStatefulWidget {
  const PublicationPage({super.key});
  @override
  ConsumerState<PublicationPage> createState() => _PublicationPageState();
}

class _PublicationPageState extends ConsumerState<PublicationPage>
    with WidgetsBindingObserver {
  late final PublicationController controller;
  bool _promptOpen = false;
  bool _viewFocused = true, _routeCurrent = true;
  bool get _appResumed =>
      WidgetsBinding.instance.lifecycleState == null ||
      WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed;
  bool get _canDisplay =>
      mounted && _viewFocused && _routeCurrent && _appResumed;
  void _updateLease() => controller.setForeground(_canDisplay);
  @override
  void initState() {
    super.initState();
    controller = ref.read(publicationProvider);
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeViewFocus(ViewFocusEvent event) {
    if (mounted && event.viewId == View.of(context).viewId) {
      _viewFocused = event.state == ViewFocusState.focused;
      _updateLease();
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) => _updateLease();
  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    controller.setForeground(false);
    super.dispose();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _routeCurrent = ModalRoute.isCurrentOf(context) ?? false;
    _updateLease();
  }

  Future<void> _issue(
    PublishedSubscription publication, {
    bool replaceUnknown = false,
  }) async {
    if (_promptOpen) return;
    _promptOpen = true;
    try {
      final seconds = await showIssueConfirmation(
        context,
        publication,
        replaceUnknown: replaceUnknown,
      );
      if (seconds == null || !mounted) return;
      // The confirmation route must be gone before acquiring a display lease.
      await WidgetsBinding.instance.endOfFrame;
      if (!mounted) return;
      _routeCurrent = ModalRoute.of(context)?.isCurrent ?? false;
      _updateLease();
      if (!_canDisplay) return;
      final result = await controller.issue(
        publication,
        seconds,
        explicitlyConfirmed: true,
        replaceUnknown: replaceUnknown,
      );
      if (result == null) return;
      if (!mounted ||
          !_canDisplay ||
          ModalRoute.of(context)?.isCurrent != true) {
        controller.discardUndisplayedSecret(result);
        return;
      }
      await showPublicationSecret(
        context,
        result,
        ref.read(managementSessionProvider),
      );
    } finally {
      _promptOpen = false;
    }
  }

  Future<void> _revoke(PublishedSubscription item) async {
    if (_promptOpen) return;
    _promptOpen = true;
    try {
      final confirmed = await confirmManagementAction(
        context,
        title: '撤销订阅访问？',
        message:
            '此链接将无法继续下载订阅。已经保存到客户端的节点凭据仍然有效，现有连接也不会因此断开。\n\n要停止节点访问，需要另外变更节点凭据并应用服务器配置。',
        action: '撤销订阅访问',
      );
      if (confirmed && mounted) await controller.revoke(item);
    } finally {
      _promptOpen = false;
    }
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: controller,
    builder: (context, _) {
      final workspace = controller.state.previous;
      final ready =
          controller.writable &&
          workspace?.activeRevision != 0 &&
          workspace?.observedRevision == workspace?.activeRevision;
      return VpPage(
        eyebrow: '独立服务器',
        title: '订阅发布',
        description: '把已生效的节点整理成订阅，单独管理访问链接。',
        maxWidth: 1200,
        action: Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            OutlinedButton.icon(
              onPressed: controller.refresh,
              icon: const Icon(Icons.refresh),
              label: const Text('刷新状态'),
            ),
            FilledButton.icon(
              key: const ValueKey('create-publication'),
              onPressed: ready
                  ? () => showPublicationEditor(context, controller)
                  : null,
              icon: const Icon(Icons.add),
              label: const Text('创建订阅'),
            ),
          ],
        ),
        children: [
          if (controller.state is! Loaded)
            LoadNotice(controller.state, retry: controller.refresh),
          if (controller.issueRecovery == null &&
              (controller.mutation is! MutationIdle ||
                  controller.notice != null))
            PublicationMutationNotice(controller: controller),
          if (workspace != null && !ready && !controller.blocked)
            const VpNotice(
              title: '等待实际运行状态',
              message: '创建或重新发布前，需要服务器观测到当前配置已生效。保存配置、凭据生成或管理页可达都不等于节点可连接。',
            ),
          if (controller.issueRecovery != null)
            _IssueRecoveryPanel(
              controller: controller,
              rotate: (item) => _issue(item, replaceUnknown: true),
            ),
          if (workspace != null && workspace.publications.isEmpty)
            VpEmpty(
              title: '还没有订阅',
              message: '选择已生效的监听与用户，明确客户端连接地址，再生成独立的订阅访问链接。',
              action: ready
                  ? TextButton(
                      onPressed: () =>
                          showPublicationEditor(context, controller),
                      child: const Text('选择发布节点 →'),
                    )
                  : null,
            ),
          if (workspace != null)
            for (final item in workspace.publications)
              _PublicationCard(
                item: item,
                currentRevision: workspace.activeRevision,
                enabled: controller.writable,
                canRepublish: ready,
                edit: () =>
                    showPublicationEditor(context, controller, existing: item),
                issue: () => _issue(item),
                revoke: () => _revoke(item),
              ),
          const VpNotice(
            title: '订阅链接与节点凭据是两种权限',
            message:
                '撤销或轮换订阅链接只影响后续下载。已经导入的节点不会自动失效。公网 HTTPS、证书与服务器可达性需要独立部署和验证。',
          ),
        ],
      );
    },
  );
}

class PublicationMutationNotice extends StatelessWidget {
  const PublicationMutationNotice({super.key, required this.controller});
  final PublicationController controller;
  @override
  Widget build(BuildContext context) {
    final state = controller.mutation;
    if (state is MutationUncertain && controller.issueRecovery == null) {
      return VpNotice(
        title: '操作结果待确认',
        message: controller.canRetryOriginal
            ? '不会创建新操作。可以使用原幂等标识恢复安全回执。'
            : '会话已变化，不会跨会话重发原操作。请保留原操作标识并核对服务器安全记录。',
        tone: VpTone.warning,
        action: controller.canRetryOriginal
            ? OutlinedButton(
                onPressed: controller.retryOriginal,
                child: const Text('恢复原操作结果'),
              )
            : null,
      );
    }
    if (controller.issueRecovery != null)
      return VpNotice(
        title: '访问链接结果待处理',
        message: '请回到订阅发布，读取安全状态后再明确选择是否轮换。不会自动重发。',
        tone: VpTone.warning,
        action: TextButton(
          onPressed: () => context.go('/publications'),
          child: const Text('前往订阅发布'),
        ),
      );
    if (state is MutationRunning) return VpLoading(label: state.label);
    if (state is MutationFailed) return FailurePanel(state.error);
    if (controller.notice != null)
      return VpNotice(title: controller.notice!, message: '不会据此推断隧道已启动或协议已认证。');
    return const SizedBox.shrink();
  }
}

class _IssueRecoveryPanel extends StatelessWidget {
  const _IssueRecoveryPanel({required this.controller, required this.rotate});
  final PublicationController controller;
  final ValueChanged<PublishedSubscription> rotate;
  @override
  Widget build(BuildContext context) {
    final recovery = controller.issueRecovery!;
    return VpSection(
      title: '链接可能已签发',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(recovery.message),
          const SizedBox(height: 16),
          const Text('原链接不可重新取回。读取安全状态不会自动生成链接；确认新轮换会使之前的访问链接失效。'),
          if (controller.recoveryReadError != null) ...[
            const SizedBox(height: 16),
            FailurePanel(controller.recoveryReadError!),
          ],
          if (recovery.metadata != null) ...[
            const SizedBox(height: 16),
            Text(
              '已读取访问版本 ${recovery.metadata!.token.version} · ${tokenLabel(recovery.metadata!.token.state)}',
            ),
          ],
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              OutlinedButton(
                onPressed: controller.mutation is MutationRunning
                    ? null
                    : controller.readIssueMetadata,
                child: const Text('读取安全状态'),
              ),
              FilledButton(
                onPressed:
                    recovery.metadata == null ||
                        controller.mutation is MutationRunning
                    ? null
                    : () => rotate(recovery.metadata!),
                child: const Text('明确轮换为新链接'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _PublicationCard extends StatelessWidget {
  const _PublicationCard({
    required this.item,
    required this.currentRevision,
    required this.enabled,
    required this.canRepublish,
    required this.edit,
    required this.issue,
    required this.revoke,
  });
  final PublishedSubscription item;
  final int currentRevision;
  final bool enabled, canRepublish;
  final VoidCallback edit, issue, revoke;
  @override
  Widget build(BuildContext context) {
    final stale = item.sourceRevision != currentRevision;
    final c = VpColors.of(context);
    return VpPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 20,
            runSpacing: 12,
            children: [
              Text(item.name, style: Theme.of(context).textTheme.titleLarge),
              Text(
                !item.enabled
                    ? '已停用'
                    : stale
                    ? '需要重新发布'
                    : tokenLabel(item.token.state),
                style: Theme.of(context).textTheme.labelLarge?.copyWith(
                  color: !item.enabled || stale ? c.warning : c.textSecondary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            '${item.sources.length} 个节点 · URI 列表 · 发布来源修订 ${item.sourceRevision}',
            style: Theme.of(
              context,
            ).textTheme.bodySmall?.copyWith(color: c.textSecondary),
          ),
          if (stale) ...[
            const SizedBox(height: 12),
            const Text('服务器配置已变化。旧订阅需要显式重新发布到当前已生效修订，不能继续按旧快照下载。'),
          ],
          const SizedBox(height: 20),
          Wrap(
            spacing: 32,
            runSpacing: 12,
            children: [
              Text('访问版本 ${item.token.version}'),
              Text(
                '有效期：${item.token.expiresAt == null ? '尚未签发' : formatMoment(item.token.expiresAt!)}',
              ),
              Text(
                '最近读取：${item.lastSuccessfulReadAt == null ? '尚无记录' : formatMoment(item.lastSuccessfulReadAt!)}',
              ),
            ],
          ),
          const SizedBox(height: 24),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              OutlinedButton(
                onPressed: canRepublish ? edit : null,
                child: Text(stale ? '重新发布' : '编辑发布内容'),
              ),
              FilledButton(
                onPressed: enabled && item.enabled && !stale ? issue : null,
                child: Text(
                  item.token.state == PublicationTokenState.notIssued
                      ? '签发访问链接'
                      : '轮换访问链接',
                ),
              ),
              TextButton(
                onPressed:
                    enabled && item.token.state == PublicationTokenState.active
                    ? revoke
                    : null,
                child: const Text('撤销订阅访问'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

String tokenLabel(PublicationTokenState value) => switch (value) {
  PublicationTokenState.notIssued => '尚未签发',
  PublicationTokenState.active => '访问已启用',
  PublicationTokenState.revoked => '访问已撤销',
  PublicationTokenState.expired => '访问已过期',
};

Future<bool> confirmManagementAction(
  BuildContext context, {
  required String title,
  required String message,
  required String action,
}) async =>
    await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: SingleChildScrollView(
          child: SizedBox(width: 500, child: Text(message)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(action),
          ),
        ],
      ),
    ) ??
    false;
Future<int?> showIssueConfirmation(
  BuildContext context,
  PublishedSubscription item, {
  required bool replaceUnknown,
}) async {
  var seconds = 86400;
  var accepted = false;
  return showDialog<int>(
    context: context,
    barrierDismissible: false,
    builder: (context) => StatefulBuilder(
      builder: (context, update) => AlertDialog(
        title: Text(
          item.token.state == PublicationTokenState.notIssued && !replaceUnknown
              ? '签发订阅访问链接'
              : '轮换订阅访问链接',
        ),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(item.name, style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 16),
                const Text('新链接只展示一次。轮换会立即使此前的链接失效，但不会撤销已下载的节点凭据。'),
                const SizedBox(height: 20),
                DropdownButtonFormField<int>(
                  initialValue: seconds,
                  decoration: const InputDecoration(labelText: '访问有效期'),
                  items: const [
                    DropdownMenuItem(value: 3600, child: Text('1 小时')),
                    DropdownMenuItem(value: 86400, child: Text('1 天')),
                    DropdownMenuItem(value: 604800, child: Text('7 天')),
                    DropdownMenuItem(value: 2592000, child: Text('30 天')),
                  ],
                  onChanged: (value) {
                    if (value != null) update(() => seconds = value);
                  },
                ),
                const SizedBox(height: 16),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: accepted,
                  onChanged: (value) => update(() => accepted = value == true),
                  title: const Text('我理解链接持有人能够下载节点凭据，并确认本次签发或轮换。'),
                ),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: accepted ? () => Navigator.pop(context, seconds) : null,
            child: const Text('确认签发并仅展示一次'),
          ),
        ],
      ),
    ),
  );
}

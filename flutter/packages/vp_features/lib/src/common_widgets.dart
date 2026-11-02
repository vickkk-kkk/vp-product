import 'package:flutter/material.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'state.dart';

String formatMoment(DateTime? value) => value == null
    ? '尚无记录'
    : value.toLocal().toIso8601String().replaceFirst('T', ' ').split('.').first;
String capabilityLabel(CapabilityStatus status) => switch (status) {
  CapabilityStatus.certified => '已认证',
  CapabilityStatus.experimental => '实验',
  CapabilityStatus.pending => '待验证',
  CapabilityStatus.unsupported => '不支持',
};
String safeOrigin(String value) {
  final uri = Uri.tryParse(value);
  if (uri == null || uri.host.isEmpty) return '来源地址不可显示';
  return Uri(
    scheme: uri.scheme,
    host: uri.host,
    port: uri.hasPort ? uri.port : null,
  ).toString();
}

class FailurePanel extends StatelessWidget {
  const FailurePanel(this.failure, {super.key, this.onRetry});
  final ProductFailure failure;
  final VoidCallback? onRetry;
  @override
  Widget build(BuildContext context) => VpNotice(
    title: failure.message,
    message:
        '${failure.remediation ?? '请检查后再试。'}\n错误代码：${failure.code}${failure.diagnosticId == null ? '' : '\n诊断编号：${failure.diagnosticId}'}',
    tone: failure.outcomeUnknown ? VpTone.warning : VpTone.danger,
    live: true,
    action: onRetry == null
        ? null
        : OutlinedButton(
            onPressed: onRetry,
            child: Text(failure.outcomeUnknown ? '查询原操作' : '重新读取'),
          ),
  );
}

class LoadNotice<T> extends StatelessWidget {
  const LoadNotice(this.state, {super.key, required this.retry});
  final LoadState<T> state;
  final VoidCallback retry;
  @override
  Widget build(BuildContext context) => switch (state) {
    Loading() => const VpLoading(),
    LoadFailed(:final error, :final previous) => Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FailurePanel(error, onRetry: retry),
        if (previous != null) ...[
          const SizedBox(height: 8),
          const Text('以下为上次读取的内容，不代表当前状态；修改操作已暂时停用。'),
        ],
      ],
    ),
    Loaded() => const SizedBox.shrink(),
  };
}

class MutationNotice extends StatelessWidget {
  const MutationNotice(this.state, {super.key, this.onReconcile});
  final MutationState state;
  final VoidCallback? onReconcile;
  @override
  Widget build(BuildContext context) => switch (state) {
    MutationIdle() => const SizedBox.shrink(),
    MutationRunning(:final label) => VpLoading(label: label),
    MutationSucceeded(:final label, :final operationId) => VpNotice(
      title: label,
      message: '操作编号：$operationId',
      tone: VpTone.info,
      live: true,
    ),
    MutationFailed(:final error) => FailurePanel(error),
    MutationUncertain(:final error) => FailurePanel(
      ProductFailure(
        error.code,
        '结果尚未确认，请勿再次提交。',
        remediation: error.remediation ?? '先查询同一操作，再决定下一步。',
        outcomeUnknown: true,
        diagnosticId: error.diagnosticId,
      ),
      onRetry: onReconcile,
    ),
  };
}

class CapabilityNote extends StatelessWidget {
  const CapabilityNote(this.capability, {super.key});
  final CapabilityView capability;
  @override
  Widget build(BuildContext context) => Text(
    '${capabilityLabel(capability.status)} · ${capability.reason}',
    style: Theme.of(
      context,
    ).textTheme.bodySmall?.copyWith(color: VpColors.of(context).textSecondary),
  );
}

Future<bool> confirmRemoval(
  BuildContext context, {
  required String title,
  required String message,
  required String action,
}) async =>
    await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Text(message),
        ),
        actions: [
          TextButton(
            autofocus: true,
            onPressed: () => Navigator.pop(context, false),
            child: const Text('保留'),
          ),
          OutlinedButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(action),
          ),
        ],
      ),
    ) ??
    false;

/// Drafts never persist secrets. Escape and system back use the same discard check.
class GuardedFormDialog extends StatefulWidget {
  const GuardedFormDialog({
    super.key,
    required this.title,
    required this.dirty,
    required this.busy,
    required this.child,
    required this.actions,
  });
  final String title;
  final bool dirty, busy;
  final Widget child;
  final List<Widget> actions;
  @override
  State<GuardedFormDialog> createState() => _GuardedFormDialogState();
}

class _GuardedFormDialogState extends State<GuardedFormDialog> {
  bool leaving = false;
  bool asking = false;
  Future<void> close() async {
    if (widget.busy || asking) return;
    if (!widget.dirty) {
      Navigator.pop(context);
      return;
    }
    asking = true;
    final discard = await confirmRemoval(
      context,
      title: '放弃未保存更改？',
      message: '本次编辑尚未保存。秘密不会保存为持久化草稿。',
      action: '放弃更改',
    );
    asking = false;
    if (discard && mounted) {
      setState(() => leaving = true);
      await WidgetsBinding.instance.endOfFrame;
      if (mounted) Navigator.pop(context);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: leaving || (!widget.dirty && !widget.busy),
    onPopInvokedWithResult: (didPop, result) {
      if (!didPop) close();
    },
    child: AlertDialog(
      title: Text(widget.title),
      content: SizedBox(
        width: 512,
        child: SingleChildScrollView(child: widget.child),
      ),
      actions: [
        TextButton(
          onPressed: widget.busy ? null : close,
          child: const Text('取消'),
        ),
        ...widget.actions,
      ],
    ),
  );
}

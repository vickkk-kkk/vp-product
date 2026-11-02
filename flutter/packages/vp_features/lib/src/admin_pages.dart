import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'controllers.dart';
import 'providers.dart';
import 'state.dart';

export 'admin_overview.dart';

class ListenerPage extends ConsumerStatefulWidget {
  const ListenerPage({super.key});
  @override
  ConsumerState<ListenerPage> createState() => _ListenerPageState();
}

class _ListenerPageState extends ConsumerState<ListenerPage> {
  String query = '';
  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final snapshot = controller.state.previous;
        final writable =
            controller.state is Loaded<ManagementSnapshot> &&
            !controller.mutation.blocked;
        final listeners = snapshot?.listeners
            .where(
              (listener) =>
                  '${listener.name} ${listener.bind} ${listener.presetKey}'
                      .toLowerCase()
                      .contains(query.toLowerCase()),
            )
            .toList();
        return VpPage(
          eyebrow: snapshot?.hostLabel ?? '服务器管理',
          title: '监听',
          description: '每次修改都先生成计划，再明确确认。请求已接受不等于新端口、凭据或数据面已生效。',
          maxWidth: 1440,
          action: Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              FilledButton.icon(
                onPressed: writable ? () => context.go('/listeners/new') : null,
                icon: const Icon(Icons.add),
                label: const Text('创建节点'),
              ),
              OutlinedButton.icon(
                onPressed: snapshot == null
                    ? null
                    : () => _showPresets(context, controller, writable),
                icon: const Icon(Icons.add),
                label: const Text('查看协议模板'),
              ),
            ],
          ),
          children: [
            LoadNotice(controller.state, retry: controller.refresh),
            MutationNotice(
              controller.mutation,
              onReconcile: controller.reconcile,
            ),
            TextField(
              decoration: const InputDecoration(
                labelText: '搜索监听',
                prefixIcon: Icon(Icons.search),
              ),
              onChanged: (value) => setState(() => query = value),
            ),
            if (listeners != null && listeners.isEmpty)
              VpEmpty(
                title: snapshot!.listeners.isEmpty ? '还没有监听' : '没有匹配的监听',
                message: snapshot.listeners.isEmpty
                    ? '先查看模板的认证状态。待验证组合不能部署。'
                    : '修改搜索条件；已有监听未被删除。',
              ),
            if (listeners != null)
              for (final listener in listeners)
                VpSection(
                  title: listener.name,
                  description:
                      '${listener.presetKey} · ${listener.bind}:${listener.port}',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      VpKeyValue('期望状态', listener.desiredEnabled ? '启用' : '停用'),
                      VpKeyValue('实际状态', listener.observedState),
                      VpKeyValue('期望修订', listener.desiredRevision),
                      VpKeyValue('实际修订', listener.observedRevision ?? '尚未观测'),
                      if (listener.problem != null)
                        FailurePanel(listener.problem!),
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 12,
                        runSpacing: 8,
                        children: [
                          OutlinedButton(
                            onPressed: writable
                                ? () => _editListener(
                                    context,
                                    controller,
                                    listener: listener,
                                  )
                                : null,
                            child: const Text('编辑并预览影响'),
                          ),
                          TextButton(
                            onPressed: writable
                                ? () async {
                                    await controller.preview(
                                      (command) =>
                                          controller.api.planDeleteListener(
                                            listener.id,
                                            command,
                                          ),
                                    );
                                    if (context.mounted &&
                                        controller.plan != null)
                                      context.go('/maintenance/plan');
                                  }
                                : null,
                            child: const Text('预览删除计划'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
          ],
        );
      },
    );
  }
}

Future<void> _showPresets(
  BuildContext context,
  AdminController controller,
  bool writable,
) async {
  final presets = controller.state.previous!.presets;
  await showDialog<void>(
    context: context,
    builder: (dialogContext) => AlertDialog(
      title: const Text('协议模板与能力状态'),
      content: SizedBox(
        width: 600,
        height: 440,
        child: ListView.separated(
          itemCount: presets.length,
          separatorBuilder: (_, index) => const Divider(),
          itemBuilder: (itemContext, index) {
            final preset = presets[index];
            return ListTile(
              contentPadding: const EdgeInsets.symmetric(vertical: 8),
              title: Text(preset.name),
              subtitle: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(preset.description),
                  const SizedBox(height: 8),
                  CapabilityNote(preset.capability),
                ],
              ),
              trailing: preset.capability.runnable && writable
                  ? IconButton(
                      tooltip: '配置 ${preset.name}',
                      onPressed: () {
                        Navigator.pop(dialogContext);
                        _editListener(context, controller, preset: preset);
                      },
                      icon: const Icon(Icons.chevron_right),
                    )
                  : null,
            );
          },
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('关闭'),
        ),
      ],
    ),
  );
}

Future<void> _editListener(
  BuildContext context,
  AdminController controller, {
  ListenerView? listener,
  PresetView? preset,
}) async {
  final name = TextEditingController(text: listener?.name ?? '');
  final bind = TextEditingController(text: listener?.bind ?? '127.0.0.1');
  final port = TextEditingController(text: listener?.port.toString() ?? '');
  var enabled = listener?.desiredEnabled ?? false;
  final form = GlobalKey<FormState>();
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) => StatefulBuilder(
      builder: (context, setDialogState) => ListenableBuilder(
        listenable: Listenable.merge([controller, name, bind, port]),
        builder: (context, _) => GuardedFormDialog(
          title: listener == null ? '配置监听草稿' : '编辑监听草稿',
          busy: controller.mutation.blocked,
          dirty:
              name.text != (listener?.name ?? '') ||
              bind.text != (listener?.bind ?? '127.0.0.1') ||
              port.text != (listener?.port.toString() ?? '') ||
              enabled != (listener?.desiredEnabled ?? false),
          child: Form(
            key: form,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const VpNotice(
                  title: '不会立即改动服务器',
                  message: '下一步由服务端完整校验字段、协议参数和认证资源，再生成不可变计划。缺失参数会阻止提交。',
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: name,
                  autofocus: true,
                  maxLength: 128,
                  decoration: const InputDecoration(labelText: '监听名称'),
                  validator: (value) =>
                      (value ?? '').trim().isEmpty ? '请输入名称。' : null,
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: bind,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: '绑定地址',
                    helperText: '公网暴露、IPv6 和端口冲突由服务端预检。',
                  ),
                  validator: (value) =>
                      (value ?? '').trim().isEmpty ? '请输入绑定地址。' : null,
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: port,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                    labelText: '端口',
                    helperText: '1–65535',
                  ),
                  validator: (value) {
                    final number = int.tryParse(value ?? '');
                    return number == null || number < 1 || number > 65535
                        ? '请输入 1–65535 的整数端口。'
                        : null;
                  },
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('期望启用'),
                  subtitle: const Text('只有应用计划后才会更改运行配置'),
                  value: enabled,
                  onChanged: (value) => setDialogState(() => enabled = value),
                ),
                MutationNotice(
                  controller.mutation,
                  onReconcile: controller.reconcile,
                ),
              ],
            ),
          ),
          actions: [
            FilledButton(
              onPressed: controller.mutation.blocked
                  ? null
                  : () async {
                      if (!form.currentState!.validate()) return;
                      await controller.preview(
                        (command) => controller.api.planListener(
                          ListenerDraft(
                            name: name.text.trim(),
                            presetKey: listener?.presetKey ?? preset!.key,
                            bind: bind.text.trim(),
                            port: int.parse(port.text),
                            listenerId: listener?.id,
                            enabled: enabled,
                          ),
                          command,
                        ),
                      );
                      if (dialogContext.mounted && controller.plan != null)
                        Navigator.pop(dialogContext);
                    },
              child: const Text('校验并预览计划'),
            ),
          ],
        ),
      ),
    ),
  );
  name.dispose();
  bind.dispose();
  port.dispose();
  if (context.mounted && controller.plan != null)
    context.go('/maintenance/plan');
}

class PlanReviewPage extends ConsumerStatefulWidget {
  const PlanReviewPage({super.key});
  @override
  ConsumerState<PlanReviewPage> createState() => _PlanReviewPageState();
}

class _PlanReviewPageState extends ConsumerState<PlanReviewPage> {
  final confirmation = TextEditingController();
  @override
  void dispose() {
    confirmation.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: Listenable.merge([controller, confirmation]),
      builder: (context, _) {
        final plan = controller.plan;
        return VpPage(
          eyebrow: '服务器变更',
          title: '核对影响，再应用',
          description: '确认的是带版本和有效期的固定计划，不是仍可变化的表单。',
          maxWidth: 880,
          children: [
            MutationNotice(
              controller.mutation,
              onReconcile: controller.reconcile,
            ),
            if (plan == null)
              const VpEmpty(
                title: '没有待确认计划',
                message: '计划可能尚未创建、已经提交、过期，或服务器修订发生了变化。请回到监听重新预览。',
              )
            else ...[
              VpSection(
                title: plan.target,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    VpKeyValue('基础修订', plan.baseRevision),
                    VpKeyValue('计划有效期', formatMoment(plan.expiresAt)),
                    VpKeyValue('计划摘要', plan.hash, selectable: true),
                    for (final change in plan.changes)
                      VpKeyValue(
                        change.field,
                        '${change.before} → ${change.after}',
                      ),
                  ],
                ),
              ),
              VpSection(
                title: '受影响范围与恢复',
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    for (final impact in plan.impacts)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 12),
                        child: Text('• $impact'),
                      ),
                    Text(plan.recovery),
                  ],
                ),
              ),
              TextField(
                controller: confirmation,
                decoration: InputDecoration(
                  labelText: '输入计划确认文字',
                  helperText: plan.confirmationPhrase,
                  helperMaxLines: 4,
                ),
              ),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  FilledButton(
                    onPressed:
                        !controller.mutation.blocked &&
                            confirmation.text == plan.confirmationPhrase
                        ? () async {
                            await controller.apply(confirmation.text);
                            if (context.mounted &&
                                controller.activeOperation != null)
                              context.go(
                                '/maintenance/operations/${Uri.encodeComponent(controller.activeOperation!.id)}',
                              );
                          }
                        : null,
                    child: const Text('应用已确认计划'),
                  ),
                  TextButton(
                    onPressed: controller.mutation.blocked
                        ? null
                        : () {
                            controller.discardPlan();
                            context.go('/listeners');
                          },
                    child: const Text('放弃计划'),
                  ),
                ],
              ),
            ],
          ],
        );
      },
    );
  }
}

class OperationPage extends ConsumerStatefulWidget {
  const OperationPage({super.key, required this.operationId});
  final String operationId;
  @override
  ConsumerState<OperationPage> createState() => _OperationPageState();
}

class _OperationPageState extends ConsumerState<OperationPage> {
  @override
  void initState() {
    super.initState();
    ref.read(adminProvider).openOperation(widget.operationId);
  }

  @override
  void didUpdateWidget(covariant OperationPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.operationId != widget.operationId)
      ref.read(adminProvider).openOperation(widget.operationId);
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final candidate = controller.activeOperation;
        final operation = candidate?.id == widget.operationId
            ? candidate
            : null;
        return VpPage(
          eyebrow: '持久操作',
          title: '服务端正在记录每一步',
          description: '关闭页面只隐藏进度，不停止服务器任务。重新打开此地址可以查询同一个操作。',
          maxWidth: 880,
          children: [
            VpKeyValue('操作编号', widget.operationId, selectable: true),
            MutationNotice(
              controller.mutation,
              onReconcile: controller.reconcile,
            ),
            if (controller.operationReadError != null)
              FailurePanel(controller.operationReadError!),
            if (operation == null)
              OutlinedButton(
                onPressed: () => controller.openOperation(widget.operationId),
                child: const Text('读取操作状态'),
              )
            else
              VpSection(
                title: operation.status,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    VpKeyValue('当前阶段', operation.stage),
                    VpKeyValue('开始时间', formatMoment(operation.startedAt)),
                    Text(operation.lastMessage),
                    if (operation.error != null) ...[
                      const SizedBox(height: 16),
                      FailurePanel(operation.error!),
                    ],
                    const SizedBox(height: 24),
                    if (operation.cancellable)
                      OutlinedButton(
                        onPressed:
                            controller.mutation.blocked ||
                                controller.state is! Loaded<ManagementSnapshot>
                            ? null
                            : controller.cancelOperation,
                        child: const Text('请求取消操作'),
                      )
                    else
                      Text(
                        operation.terminal
                            ? '操作已达到服务端终态。请核对实际修订与运行结果。'
                            : '此阶段不可取消。离开页面不会停止任务。',
                      ),
                  ],
                ),
              ),
          ],
        );
      },
    );
  }
}

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'controllers.dart';
import 'providers.dart';
import 'state.dart';

export 'connection_page.dart';

/// Lazily built node rows; no eager 1000-row shrink-wrapped list.
class NodeListPage extends ConsumerStatefulWidget {
  const NodeListPage({super.key});
  @override
  ConsumerState<NodeListPage> createState() => _NodeListPageState();
}

class _NodeListPageState extends ConsumerState<NodeListPage> {
  final search = TextEditingController();
  final selected = <String>{};
  String query = '';
  @override
  void dispose() {
    search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(inventoryProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final data = controller.state.previous?.value;
        final nodes =
            data?.nodes.where((node) => node.matches(query)).toList() ??
            <NodeView>[];
        final writable =
            controller.state is Loaded<Revisioned<ClientInventory>> &&
            !controller.mutation.blocked;
        return SafeArea(
          child: CustomScrollView(
            key: const PageStorageKey('node-list'),
            slivers: [
              SliverPadding(
                padding: const EdgeInsets.fromLTRB(24, 32, 24, 24),
                sliver: SliverToBoxAdapter(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '节点',
                        style: Theme.of(context).textTheme.headlineLarge,
                      ),
                      const SizedBox(height: 8),
                      const Text('管理你的服务器与订阅节点。'),
                      const SizedBox(height: 24),
                      FilledButton.icon(
                        onPressed: () => context.push('/import'),
                        icon: const Icon(Icons.add),
                        label: const Text('导入节点'),
                      ),
                      const SizedBox(height: 24),
                      LoadNotice(controller.state, retry: controller.refresh),
                      MutationNotice(
                        controller.mutation,
                        onReconcile: controller.reconcile,
                      ),
                      const SizedBox(height: 16),
                      TextField(
                        controller: search,
                        decoration: InputDecoration(
                          labelText: '搜索节点',
                          hintText: '名称、协议、地址或来源',
                          prefixIcon: const Icon(Icons.search),
                          suffixIcon: query.isEmpty
                              ? null
                              : IconButton(
                                  tooltip: '清除搜索',
                                  onPressed: () {
                                    search.clear();
                                    setState(() => query = '');
                                  },
                                  icon: const Icon(Icons.close),
                                ),
                        ),
                        onChanged: (value) => setState(() => query = value),
                      ),
                      if (data != null && data.nodes.isNotEmpty) ...[
                        const SizedBox(height: 12),
                        Wrap(
                          spacing: 12,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            Text(
                              '当前结果 ${nodes.length} 项 · 已选择 ${selected.length} 项',
                            ),
                            TextButton(
                              onPressed: () => setState(() {
                                selected.clear();
                                selected.addAll(nodes.map((node) => node.id));
                              }),
                              child: const Text('选择当前结果'),
                            ),
                            if (selected.isNotEmpty)
                              TextButton(
                                onPressed: () => setState(selected.clear),
                                child: const Text('清除选择'),
                              ),
                            if (selected.isNotEmpty)
                              OutlinedButton(
                                onPressed: writable
                                    ? () =>
                                          _delete(controller, Set.of(selected))
                                    : null,
                                child: const Text('删除所选节点'),
                              ),
                          ],
                        ),
                      ],
                      if (data != null && nodes.isEmpty) ...[
                        const SizedBox(height: 24),
                        VpEmpty(
                          title: data.nodes.isEmpty ? '还没有节点' : '没有匹配的节点',
                          message: data.nodes.isEmpty
                              ? '导入你已有服务的节点文本；无需管理账号。'
                              : '试试其他名称、协议或来源；已有节点没有被删除。',
                          action: data.nodes.isEmpty
                              ? null
                              : TextButton(
                                  onPressed: () {
                                    search.clear();
                                    setState(() => query = '');
                                  },
                                  child: const Text('清除搜索'),
                                ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.fromLTRB(24, 0, 24, 32),
                sliver: SliverList(
                  delegate: SliverChildBuilderDelegate((context, index) {
                    final node = nodes[index];
                    final isCurrent = node.id == data?.selectedNodeId;
                    return Padding(
                      key: ValueKey(node.id),
                      padding: const EdgeInsets.only(bottom: 12),
                      child: VpPanel(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Checkbox(
                                  value: selected.contains(node.id),
                                  semanticLabel: '选择 ${node.name}',
                                  onChanged: (value) => setState(() {
                                    if (value == true) {
                                      selected.add(node.id);
                                    } else {
                                      selected.remove(node.id);
                                    }
                                  }),
                                ),
                                Expanded(
                                  child: Padding(
                                    padding: const EdgeInsets.symmetric(
                                      vertical: 8,
                                    ),
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          node.name,
                                          style: Theme.of(
                                            context,
                                          ).textTheme.titleLarge,
                                        ),
                                        const SizedBox(height: 4),
                                        Text(
                                          '${node.protocolLabel} · ${node.transportLabel} · ${node.sourceLabel}',
                                        ),
                                        if (isCurrent)
                                          const Padding(
                                            padding: EdgeInsets.only(top: 4),
                                            child: Text('✓ 当前节点'),
                                          ),
                                      ],
                                    ),
                                  ),
                                ),
                                PopupMenuButton<String>(
                                  tooltip: '${node.name} 的更多操作',
                                  onSelected: (action) {
                                    if (action == 'rename')
                                      _renameNode(context, controller, node);
                                    if (action == 'delete')
                                      _delete(controller, {node.id});
                                  },
                                  itemBuilder: (_) => [
                                    PopupMenuItem(
                                      value: 'rename',
                                      enabled: writable,
                                      child: const Text('编辑名称'),
                                    ),
                                    PopupMenuItem(
                                      value: 'delete',
                                      enabled: writable,
                                      child: const Text('删除节点'),
                                    ),
                                  ],
                                ),
                              ],
                            ),
                            Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(node.endpoint),
                                  const SizedBox(height: 8),
                                  CapabilityNote(node.capability),
                                  const SizedBox(height: 8),
                                  TextButton(
                                    onPressed: writable && !isCurrent
                                        ? () => controller.mutate(
                                            '当前节点已更新；尚未连接',
                                            (command) => controller.repository
                                                .selectNode(node.id, command),
                                          )
                                        : null,
                                    child: Text(isCurrent ? '当前节点' : '设为当前节点'),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  }, childCount: nodes.length),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Future<void> _delete(InventoryController controller, Set<String> ids) async {
    final confirmed = await confirmRemoval(
      context,
      title: '删除 ${ids.length} 个节点？',
      message: '仅删除所选本地记录，不撤销远端凭据。运行组件必须确认没有活动连接引用这些节点，否则操作会被拒绝。',
      action: '删除所选节点',
    );
    if (!confirmed || !mounted) return;
    await controller.mutate(
      '节点删除已提交',
      (command) => controller.repository.deleteNodes(ids, command),
    );
    if (mounted && controller.mutation is MutationSucceeded)
      setState(() => selected.removeAll(ids));
  }
}

Future<void> _renameNode(
  BuildContext context,
  InventoryController controller,
  NodeView node,
) async {
  final text = TextEditingController(text: node.name);
  final form = GlobalKey<FormState>();
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) => ListenableBuilder(
      listenable: Listenable.merge([controller, text]),
      builder: (context, _) => GuardedFormDialog(
        title: '编辑节点名称',
        dirty: text.text != node.name,
        busy: controller.mutation.blocked,
        child: Form(
          key: form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextFormField(
                controller: text,
                autofocus: true,
                maxLength: 128,
                decoration: const InputDecoration(
                  labelText: '名称',
                  helperText: '仅修改本地显示名称，不改变协议、凭据或连接。',
                ),
                validator: (value) =>
                    value == null || value.trim().isEmpty ? '请输入节点名称。' : null,
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
                    await controller.mutate(
                      '名称已保存',
                      (command) => controller.repository.renameNode(
                        node.id,
                        text.text.trim(),
                        command,
                      ),
                    );
                    if (dialogContext.mounted &&
                        controller.mutation is MutationSucceeded)
                      Navigator.pop(dialogContext);
                  },
            child: const Text('保存名称'),
          ),
        ],
      ),
    ),
  );
  text.dispose();
}

class SubscriptionPage extends ConsumerStatefulWidget {
  const SubscriptionPage({super.key});
  @override
  ConsumerState<SubscriptionPage> createState() => _SubscriptionPageState();
}

class _SubscriptionPageState extends ConsumerState<SubscriptionPage> {
  String? refreshing;
  ProductFailure? refreshError;
  ClientRepository? _refreshRepository;
  @override
  void dispose() {
    final repository = _refreshRepository;
    final sourceId = refreshing;
    _refreshRepository = null;
    if (sourceId != null && repository is SubscriptionRefreshLifecycle) {
      (repository as SubscriptionRefreshLifecycle).cancelSubscriptionRefresh(
        sourceId,
      );
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(inventoryProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final sources = controller.state.previous?.value.subscriptions;
        final writable =
            controller.state is Loaded<Revisioned<ClientInventory>> &&
            !controller.mutation.blocked;
        return VpPage(
          eyebrow: '本机订阅',
          title: '来源独立，更新可控',
          description: '刷新先预览变化；失败会保留上一份可用节点。来源地址中的秘密始终遮盖。',
          action: FilledButton.icon(
            onPressed: writable
                ? () => _editSubscription(context, controller)
                : null,
            icon: const Icon(Icons.add),
            label: const Text('添加订阅'),
          ),
          children: [
            LoadNotice(controller.state, retry: controller.refresh),
            MutationNotice(
              controller.mutation,
              onReconcile: controller.reconcile,
            ),
            if (refreshError != null) FailurePanel(refreshError!),
            if (sources != null && sources.isEmpty)
              const VpEmpty(
                title: '还没有订阅',
                message: '添加 HTTPS 订阅地址后，可以在保存前查看每次更新的节点变化。',
              ),
            if (sources != null)
              for (final source in sources)
                VpSection(
                  title: source.name,
                  description: safeOrigin(source.safeOrigin),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      VpKeyValue('节点数量', '${source.nodeCount}'),
                      VpKeyValue('最近尝试', formatMoment(source.lastAttempt)),
                      VpKeyValue('最近成功', formatMoment(source.lastSuccess)),
                      if (source.error != null) FailurePanel(source.error!),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 12,
                        runSpacing: 8,
                        children: [
                          OutlinedButton(
                            onPressed: writable && refreshing == null
                                ? () => _refresh(controller, source)
                                : null,
                            child: Text(
                              refreshing == source.id ? '正在读取更新…' : '预览更新',
                            ),
                          ),
                          TextButton(
                            onPressed: writable
                                ? () => _editSubscription(
                                    context,
                                    controller,
                                    source,
                                  )
                                : null,
                            child: const Text('编辑来源'),
                          ),
                          TextButton(
                            onPressed: writable
                                ? () => _deleteSource(controller, source)
                                : null,
                            child: const Text('删除来源'),
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

  Future<void> _refresh(
    InventoryController controller,
    SubscriptionView source,
  ) async {
    if (refreshing != null) return;
    final repository = controller.repository;
    _refreshRepository = repository;
    setState(() {
      refreshing = source.id;
      refreshError = null;
    });
    try {
      final preview = await repository.previewSubscriptionRefresh(source.id);
      if (!mounted) {
        if (repository is ImportPreviewLifecycle) {
          (repository as ImportPreviewLifecycle).discardPreview(preview.id);
        }
        return;
      }
      // ImportPage owns the returned preview from this point; disposal must not
      // cancel a claimed import transaction when navigating to its review page.
      _refreshRepository = null;
      await context.push('/import', extra: preview);
    } catch (error) {
      if (mounted) setState(() => refreshError = safeFailure(error));
    } finally {
      _refreshRepository = null;
      if (mounted && !controller.disposed) await controller.refresh();
      if (mounted) setState(() => refreshing = null);
    }
  }

  Future<void> _deleteSource(
    InventoryController controller,
    SubscriptionView source,
  ) async {
    final confirmed = await confirmRemoval(
      context,
      title: '删除订阅「${source.name}」？',
      message: '该来源及其节点将被删除，手动节点不受影响。正在使用的节点会阻止删除；请先断开连接。',
      action: '删除订阅与来源节点',
    );
    if (confirmed && mounted)
      await controller.mutate(
        '订阅删除已提交',
        (command) =>
            controller.repository.deleteSubscription(source.id, command),
      );
  }
}

Future<void> _editSubscription(
  BuildContext context,
  InventoryController controller, [
  SubscriptionView? source,
]) async {
  final name = TextEditingController(text: source?.name ?? '');
  final url = TextEditingController();
  final form = GlobalKey<FormState>();
  bool visible = false;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (dialogContext) => StatefulBuilder(
      builder: (context, setDialogState) => ListenableBuilder(
        listenable: Listenable.merge([controller, name, url]),
        builder: (context, _) => GuardedFormDialog(
          title: source == null ? '添加订阅' : '编辑订阅',
          dirty: name.text != (source?.name ?? '') || url.text.isNotEmpty,
          busy: controller.mutation.blocked,
          child: Form(
            key: form,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextFormField(
                  controller: name,
                  autofocus: true,
                  maxLength: 128,
                  decoration: const InputDecoration(labelText: '来源名称'),
                  validator: (value) =>
                      value == null || value.trim().isEmpty ? '请输入来源名称。' : null,
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: url,
                  obscureText: !visible,
                  autocorrect: false,
                  enableSuggestions: false,
                  keyboardType: TextInputType.url,
                  decoration: InputDecoration(
                    labelText: source == null ? 'HTTPS 订阅地址' : '新地址（留空保持原地址）',
                    helperText: '地址可能包含秘密；不会写入日志或持久化草稿。',
                    helperMaxLines: 3,
                    suffixIcon: IconButton(
                      tooltip: visible ? '隐藏地址' : '显示地址',
                      onPressed: () => setDialogState(() => visible = !visible),
                      icon: Icon(
                        visible
                            ? Icons.visibility_off_outlined
                            : Icons.visibility_outlined,
                      ),
                    ),
                  ),
                  validator: (value) {
                    if ((value ?? '').isEmpty && source != null) return null;
                    final uri = Uri.tryParse(value ?? '');
                    return uri == null ||
                            uri.scheme != 'https' ||
                            uri.host.isEmpty ||
                            uri.userInfo.isNotEmpty ||
                            uri.fragment.isNotEmpty
                        ? '请输入有效 HTTPS 地址，不使用 URL 用户信息或片段。'
                        : null;
                  },
                ),
                const SizedBox(height: 16),
                const Text('保存来源不会自动获取或连接。之后由你明确预览更新。'),
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
                      await controller.mutate(
                        '订阅来源已保存',
                        (command) => controller.repository.saveSubscription(
                          id: source?.id,
                          name: name.text.trim(),
                          replacementUrl: url.text.isEmpty ? null : url.text,
                          command: command,
                        ),
                      );
                      if (dialogContext.mounted &&
                          controller.mutation is MutationSucceeded) {
                        url.clear();
                        Navigator.pop(dialogContext);
                      }
                    },
              child: const Text('保存来源'),
            ),
          ],
        ),
      ),
    ),
  );
  name.dispose();
  url.clear();
  url.dispose();
}

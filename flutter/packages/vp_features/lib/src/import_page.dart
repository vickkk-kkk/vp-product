import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'controllers.dart';
import 'providers.dart';
import 'state.dart';

class ImportPage extends ConsumerStatefulWidget {
  const ImportPage({super.key, this.initialPreview});
  final ImportPreview? initialPreview;
  @override
  ConsumerState<ImportPage> createState() => _ImportPageState();
}

class _ImportPageState extends ConsumerState<ImportPage> {
  final text = TextEditingController();
  final selected = <String>{};
  final duplicates = <String, DuplicateResolution>{};
  bool acceptExtraction = false, leaving = false, asking = false;
  String? initializedPreview;
  late final ImportController controller;
  @override
  void initState() {
    super.initState();
    controller = ref.read(importControllerProvider);
    if (widget.initialPreview != null &&
        controller.state is! ImportSaving &&
        controller.state is! ImportUncertain) {
      controller.state = ImportReview(widget.initialPreview!);
    }
  }

  @override
  void dispose() {
    controller.cancelParsing();
    controller.edit();
    text.clear();
    text.dispose();
    super.dispose();
  }

  Future<void> leave() async {
    if (asking || controller.state is ImportSaving) return;
    if (controller.state is ImportParsing) controller.cancelParsing();
    asking = true;
    final discard =
        text.text.isEmpty ||
        await confirmRemoval(
          context,
          title: '放弃输入？',
          message: '尚未导入的原始文本将被清除，不会保存为草稿。',
          action: '清除并返回',
        );
    asking = false;
    if (discard && mounted) {
      text.clear();
      setState(() => leaving = true);
      await WidgetsBinding.instance.endOfFrame;
      if (mounted) Navigator.pop(context);
    }
  }

  @override
  Widget build(BuildContext context) {
    final inventory = ref.watch(inventoryProvider);
    return ListenableBuilder(
      listenable: Listenable.merge([controller, inventory, text]),
      builder: (context, _) {
        final state = controller.state;
        final preview = state is ImportReview ? state.preview : null;
        if (preview != null && initializedPreview != preview.id) {
          initializedPreview = preview.id;
          selected.clear();
          duplicates.clear();
          acceptExtraction = false;
          selected.addAll(
            preview.items
                .where(
                  (item) =>
                      item.status == ImportItemStatus.ready &&
                      item.action != ImportAction.remove,
                )
                .map((item) => item.id),
          );
        }
        return PopScope(
          canPop:
              leaving ||
              (text.text.isEmpty &&
                  state is! ImportSaving &&
                  state is! ImportParsing),
          onPopInvokedWithResult: (didPop, result) {
            if (!didPop) leave();
          },
          child: Scaffold(
            appBar: AppBar(
              title: const Text('导入节点'),
              leading: IconButton(
                tooltip: '返回',
                onPressed: leave,
                icon: const Icon(Icons.arrow_back),
              ),
            ),
            body: VpPage(
              eyebrow: '本地解析 · 不会自动连接',
              title: state is ImportComplete ? '导入结果' : '先看清，再导入',
              description: '原始内容可能包含连接秘密。解析组件不会自动访问订阅地址；部分配置无法支持时会明确列出。',
              maxWidth: 880,
              children: [
                if (state is ImportEditing) ...[
                  if (state.error != null) FailurePanel(state.error!),
                  LoadNotice(inventory.state, retry: inventory.refresh),
                  TextField(
                    controller: text,
                    maxLines: 8,
                    minLines: 5,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: '节点 URI 或节点列表',
                      alignLabelWithHint: true,
                      helperText: '请主动粘贴。不会自动读取剪贴板。',
                      helperMaxLines: 3,
                    ),
                  ),
                  FilledButton(
                    onPressed:
                        inventory.state is Loaded<Revisioned<ClientInventory>>
                        ? () async {
                            await controller.parse(
                              text.text,
                              inventory.state.previous!.revision,
                            );
                            if (mounted && controller.state is ImportReview)
                              text.clear();
                          }
                        : null,
                    child: const Text('解析并预览'),
                  ),
                  const VpNotice(
                    title: '更多导入方式尚未接入',
                    message: '文件、二维码相机和图片导入需要受验证的平台适配器。当前不会显示可点击的假扫描入口。',
                  ),
                ],
                if (state is ImportParsing) ...[
                  const VpLoading(label: '正在本地解析，尚未保存任何节点…'),
                  TextButton(
                    onPressed: controller.cancelParsing,
                    child: const Text('取消解析'),
                  ),
                ],
                if (preview != null) ...[
                  if (state is ImportReview && state.error != null)
                    FailurePanel(state.error!),
                  for (final warning in preview.warnings)
                    VpNotice(
                      title: '请检查导入范围',
                      message: warning,
                      tone: VpTone.warning,
                    ),
                  for (final item in preview.items)
                    VpPanel(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          CheckboxListTile(
                            contentPadding: EdgeInsets.zero,
                            controlAffinity: ListTileControlAffinity.leading,
                            title: Text(item.safeName),
                            subtitle: Text(
                              '${_actionLabel(item.action)} · ${_statusLabel(item.status)} · ${item.explanation}',
                            ),
                            value: selected.contains(item.id),
                            onChanged: item.selectable
                                ? (value) => setState(() {
                                    if (value == true) {
                                      selected.add(item.id);
                                    } else {
                                      selected.remove(item.id);
                                      duplicates.remove(item.id);
                                    }
                                  })
                                : null,
                          ),
                          for (final field in item.fields.entries)
                            VpKeyValue(field.key, field.value),
                          if (item.status == ImportItemStatus.duplicate &&
                              selected.contains(item.id))
                            DropdownButtonFormField<DuplicateResolution>(
                              initialValue: duplicates[item.id],
                              decoration: const InputDecoration(
                                labelText: '重复项处理方式',
                              ),
                              items: [
                                for (final resolution
                                    in item.allowedResolutions)
                                  DropdownMenuItem(
                                    value: resolution,
                                    child: Text(_resolutionLabel(resolution)),
                                  ),
                              ],
                              onChanged: (value) => setState(() {
                                if (value != null) duplicates[item.id] = value;
                              }),
                            ),
                        ],
                      ),
                    ),
                  if (preview.requiresExplicitNodeExtraction)
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      value: acceptExtraction,
                      onChanged: (value) =>
                          setState(() => acceptExtraction = value ?? false),
                      title: const Text('仅导入可识别节点'),
                      subtitle: const Text('我理解未支持的规则、DNS、策略组等配置不会被应用。'),
                    ),
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      FilledButton(
                        onPressed: selected.isEmpty
                            ? null
                            : () async {
                                await controller.commit(
                                  ImportSelection(
                                    selectedIds: Set.unmodifiable(selected),
                                    duplicates: Map.unmodifiable({
                                      for (final entry in duplicates.entries)
                                        if (selected.contains(entry.key))
                                          entry.key: entry.value,
                                    }),
                                    acceptNodeExtraction: acceptExtraction,
                                  ),
                                );
                                if (controller.state is ImportComplete)
                                  await inventory.refresh();
                              },
                        child: Text(
                          '应用选中 ${selected.length} 项（删除 ${preview.items.where((item) => item.action == ImportAction.remove && selected.contains(item.id)).length} 项）',
                        ),
                      ),
                      TextButton(
                        onPressed: controller.edit,
                        child: const Text('返回修改输入'),
                      ),
                    ],
                  ),
                ],
                if (state is ImportSaving)
                  const VpLoading(label: '正在保存已确认的选择；请等待事务结果…'),
                if (state is ImportUncertain) ...[
                  FailurePanel(
                    ProductFailure(
                      state.error.code,
                      '保存结果尚未确认。',
                      remediation: '不能再次导入。请先查询原操作；离开此页不会撤销已提交事务。',
                      outcomeUnknown: true,
                    ),
                    onRetry: () async {
                      await controller.reconcile();
                      if (controller.state is ImportComplete)
                        await inventory.refresh();
                    },
                  ),
                ],
                if (state is ImportComplete) ...[
                  VpNotice(
                    title:
                        '已导入 ${state.result.imported} 项，删除 ${state.result.removed} 项，${state.result.rejected.length} 项未导入',
                    message:
                        '操作编号：${state.result.operationId}\n保存不会自动连接或选择其他节点；删除已选节点后需重新选择。',
                    tone: state.result.rejected.isEmpty
                        ? VpTone.info
                        : VpTone.warning,
                  ),
                  for (final entry in state.result.rejected.entries)
                    FailurePanel(entry.value),
                  FilledButton(
                    onPressed: () {
                      text.clear();
                      Navigator.pop(context);
                    },
                    child: const Text('返回节点列表'),
                  ),
                ],
              ],
            ),
          ),
        );
      },
    );
  }
}

String _statusLabel(ImportItemStatus status) => switch (status) {
  ImportItemStatus.ready => '可导入',
  ImportItemStatus.duplicate => '重复项',
  ImportItemStatus.unsupported => '不支持',
  ImportItemStatus.malformed => '内容损坏',
};
String _resolutionLabel(DuplicateResolution resolution) => switch (resolution) {
  DuplicateResolution.keepExisting => '保留原节点',
  DuplicateResolution.updateSameSource => '更新同源节点',
  DuplicateResolution.saveCopy => '另存副本',
};

String _actionLabel(ImportAction action) => switch (action) {
  ImportAction.add => '新增',
  ImportAction.update => '更新',
  ImportAction.remove => '删除',
};

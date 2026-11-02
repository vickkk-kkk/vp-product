import 'package:flutter/material.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'publication_controller.dart';
import 'publication_page.dart' show PublicationMutationNotice;
import 'state.dart';

Future<void> showPublicationEditor(
  BuildContext context,
  PublicationController controller, {
  PublishedSubscription? existing,
}) => showDialog<void>(
  context: context,
  barrierDismissible: false,
  builder: (_) =>
      _PublicationEditor(controller: controller, existing: existing),
);

class _SourceFields {
  _SourceFields({this.candidate, this.original})
    : selected = original != null,
      host = TextEditingController(text: original?.host ?? ''),
      port = TextEditingController(text: original?.port.toString() ?? '');
  final PublicationSourceCandidate? candidate;
  final PublicationSourceMapping? original;
  final TextEditingController host, port;
  bool selected;
  bool securityConfirmed = false;
  String get listenerId => candidate?.listenerId ?? original!.listenerId;
  String get userId => candidate?.userId ?? original!.userId;
  bool get supported =>
      candidate?.selectable == true &&
      candidate?.securityKind == 'none' &&
      (original?.security.kind ?? 'none') == 'none';
  String get reason => candidate == null
      ? '此监听或用户已不在当前配置中，请移除后重新选择。'
      : !candidate!.selectable
      ? candidate!.reason
      : candidate!.securityKind != 'none' ||
            (original?.security.kind ?? 'none') != 'none'
      ? '当前发布器尚不能重新发布此安全模式。保留原映射供核对，不会自动降级或删除。'
      : '';
  PublicationSourceMapping mapping() => PublicationSourceMapping(
    listenerId: listenerId,
    userId: userId,
    host: host.text.trim(),
    port: int.parse(port.text),
    security: original?.security ?? const PublicationSecurityNone(),
  );
  void dispose() {
    host.dispose();
    port.dispose();
  }
}

class _PublicationEditor extends StatefulWidget {
  const _PublicationEditor({required this.controller, this.existing});
  final PublicationController controller;
  final PublishedSubscription? existing;
  @override
  State<_PublicationEditor> createState() => _PublicationEditorState();
}

class _PublicationEditorState extends State<_PublicationEditor> {
  final form = GlobalKey<FormState>();
  late final TextEditingController name;
  final sources = <_SourceFields>[];
  bool enabled = true, confirmed = false;
  String? selectionError;
  @override
  void initState() {
    super.initState();
    name = TextEditingController(text: widget.existing?.name ?? '');
    enabled = widget.existing?.enabled ?? true;
    final candidates =
        widget.controller.state.previous?.sources ??
        const <PublicationSourceCandidate>[];
    final existing =
        widget.existing?.sources ?? const <PublicationSourceMapping>[];
    for (final candidate in candidates) {
      final matching = existing
          .where(
            (item) =>
                item.listenerId == candidate.listenerId &&
                item.userId == candidate.userId,
          )
          .firstOrNull;
      sources.add(_SourceFields(candidate: candidate, original: matching));
    }
    for (final old in existing) {
      if (!candidates.any(
        (item) =>
            item.listenerId == old.listenerId && item.userId == old.userId,
      ))
        sources.add(_SourceFields(original: old));
    }
  }

  @override
  void dispose() {
    name.dispose();
    for (final fields in sources) {
      fields.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    final selected = sources.where((item) => item.selected).toList();
    if (!form.currentState!.validate()) return;
    if (selected.isEmpty ||
        selected.any((item) => !item.supported || !item.securityConfirmed) ||
        !confirmed) {
      setState(() => selectionError = '请选择可用的已生效节点，并逐项确认连接地址与安全映射。');
      return;
    }
    final before = widget.controller.completedActions;
    final draft = PublicationDraft(
      name: name.text.trim(),
      enabled: enabled,
      sources: selected.map((item) => item.mapping()).toList(),
    );
    if (widget.existing == null) {
      await widget.controller.create(draft);
    } else {
      await widget.controller.replace(widget.existing!, draft);
    }
    if (mounted && widget.controller.completedActions > before)
      Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
    listenable: widget.controller,
    builder: (context, _) {
      final c = widget.controller;
      return AlertDialog(
        title: Text(widget.existing == null ? '创建订阅' : '编辑并重新发布'),
        content: SizedBox(
          width: 720,
          child: SingleChildScrollView(
            child: Form(
              key: form,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextFormField(
                    controller: name,
                    enabled: !c.blocked,
                    maxLength: 128,
                    decoration: const InputDecoration(
                      labelText: '订阅名称',
                      hintText: '例如：个人设备',
                    ),
                    validator: (value) =>
                        (value ?? '').trim().isEmpty ? '请输入订阅名称。' : null,
                  ),
                  const SizedBox(height: 20),
                  Text(
                    '选择已生效的监听与用户',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    '绑定地址不是对外连接地址。请明确填写客户端实际使用的主机和端口；这里不会自动推断或配置公网入口。',
                  ),
                  const SizedBox(height: 20),
                  if (sources.isEmpty)
                    const VpNotice(
                      title: '暂时没有可发布来源',
                      message: '先完成节点配置应用，并等候服务器实际运行观测。',
                    ),
                  for (final source in sources) ...[
                    VpPanel(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          CheckboxListTile(
                            contentPadding: EdgeInsets.zero,
                            value: source.selected,
                            onChanged:
                                c.blocked ||
                                    (!source.supported && !source.selected)
                                ? null
                                : (value) => setState(() {
                                    source.selected = value == true;
                                    selectionError = null;
                                  }),
                            title: Text(
                              source.candidate?.listenerName ?? '已移除的监听',
                            ),
                            subtitle: Text('用户 ${source.userId}'),
                          ),
                          if (source.reason.isNotEmpty) Text(source.reason),
                          if (source.candidate != null)
                            Text(
                              '服务器绑定 ${source.candidate!.bindAddress}:${source.candidate!.bindPort} · ${source.candidate!.protocol}/${source.candidate!.transport}',
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                          if (source.selected) ...[
                            const SizedBox(height: 20),
                            TextFormField(
                              controller: source.host,
                              enabled: !c.blocked,
                              autocorrect: false,
                              decoration: const InputDecoration(
                                labelText: '客户端连接主机',
                                helperText: '只填域名或 IP，不含协议、账号和路径。',
                              ),
                              validator: (value) => !source.selected
                                  ? null
                                  : validPublicationHost(value)
                                  ? null
                                  : '请输入明确的域名或 IP。',
                            ),
                            const SizedBox(height: 16),
                            TextFormField(
                              controller: source.port,
                              enabled: !c.blocked,
                              keyboardType: TextInputType.number,
                              decoration: const InputDecoration(
                                labelText: '客户端连接端口',
                              ),
                              validator: (value) {
                                final number = int.tryParse(value ?? '');
                                return !source.selected ||
                                        (number != null &&
                                            number > 0 &&
                                            number <= 65535)
                                    ? null
                                    : '请输入 1–65535 的整数端口。';
                              },
                            ),
                            const SizedBox(height: 16),
                            Text(
                              source.original != null &&
                                      source.original!.security.kind != 'none'
                                  ? '保留现有 ${source.original!.security.kind.toUpperCase()} 安全映射，不修改信任参数。此版本尚未提供该模式的安全编辑器。'
                                  : '客户端安全映射：无额外 TLS。不会替你开启证书校验，也不会假定公网链路已经加密。',
                            ),
                            CheckboxListTile(
                              contentPadding: EdgeInsets.zero,
                              value: source.securityConfirmed,
                              onChanged: c.blocked
                                  ? null
                                  : (value) => setState(
                                      () => source.securityConfirmed =
                                          value == true,
                                    ),
                              title: const Text('我已核对这个节点的客户端连接地址和安全映射。'),
                            ),
                          ],
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('允许订阅访问'),
                    subtitle: const Text('停用会撤销旧链接；重新启用不会恢复旧链接，需要重新签发。'),
                    value: enabled,
                    onChanged: c.blocked
                        ? null
                        : (value) => setState(() => enabled = value),
                  ),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    value: confirmed,
                    onChanged: c.blocked
                        ? null
                        : (value) => setState(() => confirmed = value == true),
                    title: const Text('我确认向持有订阅链接的人发布所选节点的连接凭据。'),
                  ),
                  if (selectionError != null)
                    Text(
                      selectionError!,
                      style: TextStyle(color: VpColors.of(context).danger),
                    ),
                  PublicationMutationNotice(controller: c),
                ],
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: c.mutation is MutationRunning
                ? null
                : () => Navigator.pop(context),
            child: const Text('关闭'),
          ),
          FilledButton(
            onPressed: c.writable && confirmed ? _save : null,
            child: Text(widget.existing == null ? '创建发布内容' : '按当前生效修订重新发布'),
          ),
        ],
      );
    },
  );
}

bool validPublicationHost(String? input) {
  final value = (input ?? '').trim();
  if (value.isEmpty ||
      value.length > 253 ||
      RegExp(r'[\s/@?#\[\]]').hasMatch(value) ||
      value.contains('://'))
    return false;
  if (value.contains(':')) {
    final parsed = Uri.tryParse('http://[$value]');
    return parsed != null && parsed.host == value.toLowerCase();
  }
  return true;
}

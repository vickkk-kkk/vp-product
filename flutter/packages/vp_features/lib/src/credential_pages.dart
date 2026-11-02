import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'controllers.dart';
import 'providers.dart';
import 'publication_page.dart';
import 'state.dart';

class ManagementCredentialsPage extends ConsumerWidget {
  const ManagementCredentialsPage({super.key});
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final controller = ref.watch(publicationProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final workspace = controller.state.previous;
        return VpPage(
          eyebrow: '独立服务器',
          title: '连接凭据',
          description: '由服务器生成并保存在加密凭据库中，不需要手工填写内部引用。',
          maxWidth: 1100,
          action: Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              OutlinedButton.icon(
                onPressed: controller.refresh,
                icon: const Icon(Icons.refresh),
                label: const Text('刷新'),
              ),
              FilledButton.icon(
                onPressed:
                    controller.writable && workspace?.supportsUuid == true
                    ? () => context.go('/listeners/new')
                    : null,
                icon: const Icon(Icons.add),
                label: const Text('创建节点'),
              ),
            ],
          ),
          children: [
            if (controller.state is! Loaded)
              LoadNotice(controller.state, retry: controller.refresh),
            if (controller.mutation is! MutationIdle ||
                controller.notice != null ||
                controller.issueRecovery != null)
              PublicationMutationNotice(controller: controller),
            VpNotice(
              title: workspace?.supportsUuid == true
                  ? '此服务器支持 UUID 凭据生成'
                  : '尚无可用的 UUID 生成能力',
              message:
                  '这只是凭据生成能力，不是协议认证或节点已启动。其它密码组合与证书流程尚未接入，不会要求你提供暂时用不到的密钥。',
            ),
            if (workspace != null && workspace.credentials.isEmpty)
              const VpEmpty(
                title: '还没有连接凭据',
                message: '在创建节点向导中明确确认生成。完成配置校验、计划确认与实际应用后，节点才可能生效。',
              ),
            if (workspace != null)
              for (final item in workspace.credentials)
                VpPanel(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Wrap(
                        alignment: WrapAlignment.spaceBetween,
                        spacing: 20,
                        runSpacing: 12,
                        children: [
                          Text(
                            item.kind.isUuid
                                ? 'UUID 连接凭据'
                                : item.kind.toString(),
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          Text(
                            item.state == ManagedCredentialState.available
                                ? '可用于配置'
                                : '已回收',
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        '标识 ${credentialDisplayId(item.id)} · 创建于 ${formatMoment(item.createdAt)}',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                      const SizedBox(height: 16),
                      Align(
                        alignment: Alignment.centerLeft,
                        child: OutlinedButton(
                          onPressed:
                              controller.writable &&
                                  item.state == ManagedCredentialState.available
                              ? () async {
                                  final confirmed = await confirmManagementAction(
                                    context,
                                    title: '回收未使用的凭据？',
                                    message:
                                        '只有未被草稿、计划、运行配置或恢复历史引用的凭据才能回收。\n\n这不是撤销在线用户权限，也不会让正在使用的节点凭据自动失效。服务端会拒绝仍被引用的对象。',
                                    action: '确认回收',
                                  );
                                  if (confirmed && context.mounted)
                                    await controller.retire(item);
                                }
                              : null,
                          child: const Text('回收未使用凭据'),
                        ),
                      ),
                    ],
                  ),
                ),
            const SizedBox(
              width: double.infinity,
              child: VpSection(
                title: '证书与其它凭据',
                child: Text(
                  'TLS / REALITY 证书、复合用户名密码及轮换向导尚未完成集成。此处不会伪造可用能力，也不会收集无法正确应用的秘密。',
                ),
              ),
            ),
          ],
        );
      },
    );
  }
}

class NewUuidListenerPage extends ConsumerStatefulWidget {
  const NewUuidListenerPage({super.key});
  @override
  ConsumerState<NewUuidListenerPage> createState() =>
      _NewUuidListenerPageState();
}

class _NewUuidListenerPageState extends ConsumerState<NewUuidListenerPage> {
  final form = GlobalKey<FormState>();
  final name = TextEditingController(), port = TextEditingController();
  final listenerId = 'listener_${newRequestId()}',
      userId = 'user_${newRequestId()}';
  String bind = '127.0.0.1';
  String? credentialId;
  bool developmentConsent = false, _promptOpen = false, _preparing = false;
  @override
  void dispose() {
    name.dispose();
    port.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    if (_promptOpen) return;
    _promptOpen = true;
    try {
      final confirmed = await confirmManagementAction(
        context,
        title: '生成一份 UUID 连接凭据？',
        message:
            '服务器会生成随机 UUID 并写入加密凭据库。页面只接收安全标识，不显示原始凭据。\n\n生成后还需要配置监听、校验并应用。此步骤不会启动隧道。',
        action: '确认生成凭据',
      );
      if (!confirmed || !mounted) return;
      final controller = ref.read(publicationProvider);
      final before = controller.completedActions;
      await controller.generateCredential();
      if (mounted && controller.completedActions > before)
        setState(() => credentialId = controller.generatedCredential?.id);
    } finally {
      _promptOpen = false;
    }
  }

  Future<void> _prepare(ManagedCredential credential) async {
    if (_preparing || !developmentConsent || !form.currentState!.validate())
      return;
    _preparing = true;
    try {
      final controller = ref.read(publicationProvider);
      final before = controller.completedActions;
      await controller.prepareListener(
        NewUuidListenerInput(
          listenerId: listenerId,
          userId: userId,
          name: name.text.trim(),
          bindAddress: bind,
          port: int.parse(port.text),
        ),
        credential,
      );
      if (mounted &&
          controller.completedActions > before &&
          controller.preparedPlan != null)
        await _showPlan();
    } finally {
      _preparing = false;
    }
  }

  Future<void> _showPlan() async {
    final controller = ref.read(publicationProvider),
        admin = ref.read(adminProvider);
    final plan = controller.preparedPlan;
    if (plan == null || controller.blocked) return;
    await admin.refresh();
    if (!mounted) return;
    if (admin.adoptPreparedPlan(plan)) {
      context.go('/maintenance/plan');
    } else {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('服务器状态或计划已变化，请重新读取并校验。')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(publicationProvider),
        admin = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: Listenable.merge([controller, admin]),
      builder: (context, _) {
        final workspace = controller.state.previous;
        final available =
            workspace?.credentials
                .where(
                  (item) =>
                      item.state == ManagedCredentialState.available &&
                      item.kind.isUuid,
                )
                .toList() ??
            <ManagedCredential>[];
        final credential = available
            .where((item) => item.id == credentialId)
            .firstOrNull;
        final canDevelop =
            workspace?.developmentBuild == true &&
            workspace?.supportsUuid == true;
        return VpPage(
          eyebrow: '监听 / 新建',
          title: '一步一步，配置你的节点',
          description: '连接凭据 → 监听草稿 → 校验与计划 → 明确应用。',
          maxWidth: 920,
          action: TextButton.icon(
            onPressed: () => context.go('/listeners'),
            icon: const Icon(Icons.arrow_back, size: 18),
            label: const Text('返回监听'),
          ),
          children: [
            if (controller.state is! Loaded)
              LoadNotice(controller.state, retry: controller.refresh),
            if (controller.mutation is! MutationIdle ||
                controller.notice != null ||
                controller.issueRecovery != null)
              PublicationMutationNotice(controller: controller),
            if (admin.mutation.blocked)
              MutationNotice(admin.mutation, onReconcile: admin.reconcile),
            const VpNotice(
              title: '当前只提供回环开发路径',
              message:
                  'UUID + VLESS / TCP / 无 TLS。它不是公网可用模板或协议认证。是否能应用仍由真实服务端校验与计划决定，默认未接运行组件的服务器会拒绝。',
              tone: VpTone.warning,
            ),
            if (!canDevelop)
              const VpNotice(
                title: '此服务器暂不能使用该向导',
                message: '需要服务端实际声明开发构建与 UUID 生成能力。不会根据模板名称猜测运行能力。',
              ),
            VpSection(
              title: '01  连接凭据',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text('明确生成新凭据，或选择这台服务器已有的 UUID 凭据。无需输入内部凭据引用。'),
                  const SizedBox(height: 20),
                  DropdownButtonFormField<String>(
                    key: ValueKey(credential?.id ?? 'no-credential'),
                    initialValue: credential?.id,
                    isExpanded: true,
                    decoration: const InputDecoration(labelText: '使用哪份凭据'),
                    items: [
                      for (final item in available)
                        DropdownMenuItem(
                          value: item.id,
                          child: Text(
                            'UUID · ${credentialDisplayId(item.id)}',
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                    ],
                    onChanged: controller.writable
                        ? (value) => setState(() => credentialId = value)
                        : null,
                  ),
                  const SizedBox(height: 16),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: OutlinedButton.icon(
                      key: const ValueKey('generate-node-credential'),
                      onPressed: controller.writable && canDevelop
                          ? _generate
                          : null,
                      icon: const Icon(Icons.key_outlined),
                      label: const Text('生成新连接凭据'),
                    ),
                  ),
                  if (credential != null) ...[
                    const SizedBox(height: 12),
                    const Text('凭据已保存。尚未应用监听，也尚未启动隧道。'),
                  ],
                ],
              ),
            ),
            VpSection(
              title: '02  监听草稿',
              child: Form(
                key: form,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    TextFormField(
                      controller: name,
                      enabled: controller.writable && canDevelop,
                      maxLength: 128,
                      decoration: const InputDecoration(
                        labelText: '节点名称',
                        hintText: '例如：本机开发验证',
                      ),
                      validator: (value) =>
                          (value ?? '').trim().isEmpty ? '请输入名称。' : null,
                    ),
                    const SizedBox(height: 16),
                    DropdownButtonFormField<String>(
                      isExpanded: true,
                      itemHeight: null,
                      initialValue: bind,
                      decoration: const InputDecoration(labelText: '回环绑定地址'),
                      items: const [
                        DropdownMenuItem(
                          value: '127.0.0.1',
                          child: Text('127.0.0.1 · IPv4 回环'),
                        ),
                        DropdownMenuItem(
                          value: '::1',
                          child: Text('::1 · IPv6 回环'),
                        ),
                      ],
                      onChanged: controller.writable && canDevelop
                          ? (value) {
                              if (value != null) setState(() => bind = value);
                            }
                          : null,
                    ),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: port,
                      enabled: controller.writable && canDevelop,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(
                        labelText: '监听端口',
                        helperText: '端口占用会由服务端预检，不会修改防火墙。',
                      ),
                      validator: (value) {
                        final number = int.tryParse(value ?? '');
                        return number != null && number > 0 && number <= 65535
                            ? null
                            : '请输入 1–65535 的整数端口。';
                      },
                    ),
                    const SizedBox(height: 20),
                    const Text('协议 VLESS   /   传输 TCP   /   安全 无额外 TLS'),
                    const SizedBox(height: 12),
                    CheckboxListTile(
                      contentPadding: EdgeInsets.zero,
                      value: developmentConsent,
                      onChanged: controller.writable && canDevelop
                          ? (value) => setState(
                              () => developmentConsent = value == true,
                            )
                          : null,
                      title: const Text('我仅在回环开发环境验证此未认证组合，不将它当作公网加密服务。'),
                    ),
                  ],
                ),
              ),
            ),
            if (workspace != null)
              ExpansionTile(
                tilePadding: EdgeInsets.zero,
                title: const Text('服务器实际能力目录'),
                children: [
                  for (final preset in workspace.presets)
                    ListTile(
                      title: Text(preset.name),
                      subtitle: Text(
                        '${preset.description}\n${preset.capability.reason}',
                      ),
                      trailing: Text(capabilityLabel(preset.capability.status)),
                    ),
                ],
              ),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                FilledButton.icon(
                  onPressed:
                      controller.writable &&
                          canDevelop &&
                          developmentConsent &&
                          credential != null
                      ? () => _prepare(credential)
                      : null,
                  icon: const Icon(Icons.fact_check_outlined),
                  label: const Text('校验草稿并预览计划'),
                ),
                if (controller.preparedPlan != null)
                  OutlinedButton(
                    onPressed: controller.blocked ? null : _showPlan,
                    child: const Text('查看已生成计划'),
                  ),
              ],
            ),
            const Text('下一步只展示服务端生成的固定计划。只有再次明确确认应用后，服务器才会开始执行变更。'),
          ],
        );
      },
    );
  }
}

String credentialDisplayId(String value) =>
    value.length > 12 ? "…${value.substring(value.length - 12)}" : value;

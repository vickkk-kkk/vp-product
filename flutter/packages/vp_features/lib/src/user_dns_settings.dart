import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'controllers.dart';
import 'providers.dart';
import 'state.dart';

/// Activate in Settings only alongside the schema-v2 runtime. No resolver is
/// supplied implicitly, and storing a choice is not evidence of working DNS.
class UserDnsSettingsEditor extends ConsumerStatefulWidget {
  const UserDnsSettingsEditor({super.key});

  @override
  ConsumerState<UserDnsSettingsEditor> createState() =>
      _UserDnsSettingsEditorState();
}

class _UserDnsSettingsEditorState extends ConsumerState<UserDnsSettingsEditor> {
  final _servers = TextEditingController();
  bool _initialized = false;
  bool _dirty = false;

  @override
  void dispose() {
    _servers.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = ref.watch(inventoryProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final state = controller.state;
        final value = state.previous?.value;
        final repository = controller.repository;
        final supported = repository is ClientDnsSettingsRepository;
        final writable =
            supported &&
            state is Loaded<Revisioned<ClientInventory>> &&
            !controller.mutation.blocked;
        if (!_initialized && value != null) {
          _initialized = true;
          _servers.text = value.userDns?.servers.join('\n') ?? '';
        }
        return VpSection(
          title: 'DNS 服务器',
          description: '通过当前节点查询，不会自动改用直连。',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              LoadNotice(state, retry: controller.refresh),
              MutationNotice(
                controller.mutation,
                onReconcile: controller.reconcile,
              ),
              if (!supported)
                const VpNotice(title: '此平台暂不支持配置', message: '没有更改 DNS 设置。')
              else ...[
                Text(
                  value?.userDns == null
                      ? '尚未设置；连接前需要填写。'
                      : '已保存 ${value!.userDns!.servers.length} 个服务器。',
                ),
                const SizedBox(height: 16),
                TextField(
                  key: const ValueKey('user-dns-servers'),
                  controller: _servers,
                  enabled: writable,
                  minLines: 2,
                  maxLines: 4,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    labelText: '服务器地址',
                    helperText: '每行一个数字 IP 与端口，最多 4 个。IPv6 地址用方括号括起。',
                    helperMaxLines: 8,
                  ),
                  onChanged: (_) => setState(() => _dirty = true),
                ),
                const SizedBox(height: 16),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  children: [
                    FilledButton(
                      key: const ValueKey('save-user-dns'),
                      onPressed: writable && _dirty
                          ? () => _save(controller)
                          : null,
                      child: const Text('保存 DNS'),
                    ),
                    TextButton(
                      key: const ValueKey('clear-user-dns'),
                      onPressed: writable && value?.userDns != null
                          ? () => _clear(controller)
                          : null,
                      child: const Text('清除设置'),
                    ),
                  ],
                ),
              ],
            ],
          ),
        );
      },
    );
  }

  Future<void> _save(InventoryController controller) async {
    final servers = _servers.text
        .split(RegExp(r'\r?\n'))
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    // The authoritative data adapter validates/canonicalizes numeric endpoints.
    // Empty input is invalid; clearing is a separate, confirmed action.
    await controller.mutate(
      'DNS 设置已保存',
      (command) => (controller.repository as ClientDnsSettingsRepository)
          .saveUserDns(UserDnsSettings(servers: servers), command),
    );
    _syncAfterSuccess(controller);
  }

  Future<void> _clear(InventoryController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('清除 DNS 设置？'),
        content: const Text('清除后，需要重新设置 DNS 才能发起连接。不会自动选择其他服务器。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认清除'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await controller.mutate(
      'DNS 设置已清除',
      (command) => (controller.repository as ClientDnsSettingsRepository)
          .saveUserDns(null, command),
    );
    _syncAfterSuccess(controller);
  }

  void _syncAfterSuccess(InventoryController controller) {
    if (!mounted ||
        controller.mutation is! MutationSucceeded ||
        controller.state is! Loaded<Revisioned<ClientInventory>>)
      return;
    setState(() {
      _servers.text =
          controller.state.previous?.value.userDns?.servers.join('\n') ?? '';
      _dirty = false;
    });
  }
}

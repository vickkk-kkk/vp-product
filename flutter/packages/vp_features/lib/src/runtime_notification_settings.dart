import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'providers.dart';

/// Optional, explicit OS notification consent; never part of VPN authorization.
class RuntimeNotificationSettings extends ConsumerStatefulWidget {
  const RuntimeNotificationSettings({super.key});
  @override
  ConsumerState<RuntimeNotificationSettings> createState() =>
      _RuntimeNotificationSettingsState();
}

class _RuntimeNotificationSettingsState
    extends ConsumerState<RuntimeNotificationSettings>
    with WidgetsBindingObserver {
  RuntimeNotificationPermission? _permission;
  ProductFailure? _error;
  bool _busy = false;
  int _epoch = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refresh();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _epoch++;
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && !_busy) _refresh();
  }

  Future<void> _refresh({bool request = false}) async {
    if (_busy) return;
    final runtime = ref.read(runtimeProvider);
    if (runtime is! RuntimeNotificationControl) return;
    final epoch = ++_epoch;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final control = runtime as RuntimeNotificationControl;
      final permission = await (request
          ? control.requestNotificationPermission()
          : control.notificationPermission());
      if (mounted && epoch == _epoch) setState(() => _permission = permission);
    } catch (error) {
      if (mounted && epoch == _epoch)
        setState(() => _error = safeFailure(error));
    } finally {
      if (mounted && epoch == _epoch) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (ref.watch(runtimeProvider) is! RuntimeNotificationControl)
      return const SizedBox.shrink();
    return VpSection(
      title: '后台状态通知',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            _permission?.granted == true
                ? '通知已允许。连接运行时可从通知栏查看状态或断开。'
                : '允许通知后，可在通知栏查看运行状态和断开连接。',
          ),
          const SizedBox(height: 8),
          const Text('通知权限与 VPN 授权分开；不允许通知不会自动断开 VPN。'),
          if (_permission != null &&
              !_permission!.granted &&
              !_permission!.canRequest)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text('请在系统设置 → 应用 → VP → 通知中允许。'),
            ),
          if (_error != null) FailurePanel(_error!),
          const SizedBox(height: 12),
          Wrap(
            spacing: 12,
            children: [
              if (_permission?.canRequest == true)
                FilledButton(
                  key: const ValueKey('request-vpn-notifications'),
                  onPressed: _busy ? null : () => _refresh(request: true),
                  child: const Text('允许通知'),
                ),
              TextButton(
                onPressed: _busy ? null : _refresh,
                child: Text(_busy ? '正在读取…' : '重新读取权限'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

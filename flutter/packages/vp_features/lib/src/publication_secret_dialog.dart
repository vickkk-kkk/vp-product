import 'dart:ui' show ViewFocusEvent, ViewFocusState;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';

/// The only UI allowed to own the issued bearer URL. No state restoration, route
/// argument, history entry, widget key, logging, analytics or automatic clipboard.
Future<void> showPublicationSecret(
  BuildContext context,
  OneTimePublicationSecret result,
  ManagementSession session,
) async {
  if (!context.mounted) {
    result.dispose();
    return;
  }
  try {
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) =>
          _PublicationSecretDialog(result: result, session: session),
    );
  } finally {
    result.dispose();
  }
}

class _PublicationSecretDialog extends StatefulWidget {
  const _PublicationSecretDialog({required this.result, required this.session});
  final OneTimePublicationSecret result;
  final ManagementSession session;
  @override
  State<_PublicationSecretDialog> createState() =>
      _PublicationSecretDialogState();
}

class _PublicationSecretDialogState extends State<_PublicationSecretDialog>
    with WidgetsBindingObserver {
  String? _display;
  bool _copied = false;
  String? _copyError;
  ManagementSessionEpoch? _epochs;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (widget.session is ManagementSessionEpoch) {
      _epochs = widget.session as ManagementSessionEpoch;
      _epochs!.addSessionListener(_invalidate);
    }
    final active = WidgetsBinding.instance.lifecycleState;
    if (widget.session.authenticated &&
        (_epochs == null ||
            _epochs!.sessionEpoch == widget.result.sessionEpoch) &&
        (active == null || active == AppLifecycleState.resumed)) {
      _display = widget.result.takeOnce();
    } else {
      widget.result.dispose();
    }
  }

  void _invalidate() {
    if (!mounted) return;
    setState(() {
      _display = null;
      _copyError = null;
      _copied = false;
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (ModalRoute.isCurrentOf(context) == false) {
      _display = null;
      _copied = false;
      _copyError = null;
      widget.result.dispose();
    }
  }

  @override
  void didChangeViewFocus(ViewFocusEvent event) {
    if (mounted &&
        event.viewId == View.of(context).viewId &&
        event.state == ViewFocusState.unfocused)
      _invalidate();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) _invalidate();
  }

  @override
  void dispose() {
    _display = null;
    widget.result.dispose();
    _epochs?.removeSessionListener(_invalidate);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _copy() async {
    final value = _display;
    if (value == null || !widget.session.authenticated) return;
    try {
      await Clipboard.setData(ClipboardData(text: value));
      if (mounted && _display != null)
        setState(() {
          _copied = true;
          _copyError = null;
        });
    } catch (_) {
      if (mounted && _display != null)
        setState(() => _copyError = '复制未完成，请检查浏览器的剪贴板权限。');
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(_display == null ? '链接展示已清除' : '保存这一次的订阅链接'),
    content: SizedBox(
      width: 560,
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_display == null)
              const Text('此链接不会再次回显。需要新的访问链接时，请回到订阅页明确轮换；轮换会使之前的链接失效。')
            else ...[
              const Text('持有此链接即可下载其中的节点凭据。请只交给可信的人，不要放入截图、工单或聊天群。'),
              const SizedBox(height: 20),
              VpPanel(
                padding: const EdgeInsets.all(16),
                child: Text(
                  _display!,
                  key: const ValueKey('one-time-subscription-link'),
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ),
              const SizedBox(height: 16),
              if (widget.result.developmentLoopback)
                const VpNotice(
                  title: '仅限本机开发验证',
                  message: '这是回环地址，手机不能通过此地址访问。它不代表已经部署公网 HTTPS。',
                  tone: VpTone.warning,
                ),
              if (!widget.result.developmentLoopback) ...[
                const SizedBox(height: 12),
                const Text('访问入口由管理员配置。本页面不代为部署 HTTPS、证书或验证手机可达性。'),
              ],
              const SizedBox(height: 16),
              const Text(
                '关闭、切换应用或窗口失焦后会清除本窗口展示。复制只会在你点击后执行；系统剪贴板可能继续保留内容，请自行妥善处理。',
              ),
              const SizedBox(height: 12),
              const Text('撤销订阅访问不会撤销已经下载的节点凭据，也不会断开已有连接。'),
              if (_copyError != null) ...[
                const SizedBox(height: 12),
                Text(_copyError!),
              ],
            ],
          ],
        ),
      ),
    ),
    actions: [
      if (_display != null)
        FilledButton.icon(
          key: const ValueKey('copy-subscription-link'),
          onPressed: _copy,
          icon: const Icon(Icons.copy_outlined),
          label: Text(_copied ? '已复制' : '复制链接'),
        ),
      OutlinedButton(
        onPressed: () {
          _invalidate();
          Navigator.pop(context);
        },
        child: const Text('关闭并清除展示'),
      ),
    ],
  );
}

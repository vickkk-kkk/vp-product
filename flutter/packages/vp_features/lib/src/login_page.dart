import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'providers.dart';

/// A separate entry composition, deliberately without authenticated navigation.
class ManagementLoginPage extends ConsumerStatefulWidget {
  const ManagementLoginPage({super.key, this.returnPath = '/overview'});
  final String returnPath;
  @override
  ConsumerState<ManagementLoginPage> createState() =>
      _ManagementLoginPageState();
}

class _ManagementLoginPageState extends ConsumerState<ManagementLoginPage> {
  final username = TextEditingController();
  final accessToken = TextEditingController();
  final form = GlobalKey<FormState>();
  bool busy = false, visible = false;
  ProductFailure? error;
  @override
  void dispose() {
    username.dispose();
    accessToken.clear();
    accessToken.dispose();
    super.dispose();
  }

  Future<void> login() async {
    if (busy || !form.currentState!.validate()) return;
    setState(() {
      busy = true;
      error = null;
    });
    // A new login must not inherit another session's cached server data.
    // Uncertain command identity remains blocked in the controller.
    ref.read(adminProvider).forgetSession();
    try {
      await ref
          .read(managementSessionProvider)
          .login(username.text.trim(), accessToken.text);
      if (!mounted) return;
      accessToken.clear();
      await ref.read(adminProvider).refresh();
      if (mounted) context.go(widget.returnPath);
    } catch (failure) {
      if (mounted) setState(() => error = safeFailure(failure));
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> logout() async {
    if (busy) return;
    setState(() {
      busy = true;
      error = null;
    });
    ref.read(adminProvider).forgetSession();
    try {
      await ref.read(managementSessionProvider).logout();
    } catch (failure) {
      if (mounted) setState(() => error = safeFailure(failure));
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = ref.watch(managementSessionProvider);
    final c = VpColors.of(context);
    final t = Theme.of(context).textTheme;
    return Scaffold(
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, box) {
            final wide =
                box.maxWidth >= 1000 &&
                MediaQuery.textScalerOf(context).scale(1) < 1.6;
            final margin = box.maxWidth < 600 ? 24.0 : 48.0;
            final content = ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (!wide) ...[
                    const _ManagementWordmark(),
                    const SizedBox(height: 44),
                  ],
                  Text(
                    session.authenticated ? '管理会话' : '欢迎回来',
                    style: t.headlineLarge?.copyWith(
                      fontSize: 32,
                      letterSpacing: -.8,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    session.authenticated ? '你已登录此管理服务。' : '登录你的独立服务器。',
                    style: t.bodyLarge?.copyWith(color: c.textSecondary),
                  ),
                  const SizedBox(height: 28),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      vertical: 14,
                      horizontal: 16,
                    ),
                    decoration: BoxDecoration(
                      color: c.surfaceSubtle,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.dns_outlined,
                          size: 20,
                          color: c.textSecondary,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                '管理入口',
                                style: t.labelSmall?.copyWith(
                                  color: c.textSecondary,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(session.originLabel, style: t.bodyMedium),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 28),
                  if (!session.canAuthenticate) ...[
                    const VpNotice(
                      title: '当前无法登录',
                      message: '请从已部署的 Web 管理入口打开此页面。',
                    ),
                    const SizedBox(height: 20),
                  ],
                  if (error != null) ...[
                    FailurePanel(error!),
                    const SizedBox(height: 20),
                  ],
                  if (session.authenticated) ...[
                    const Text('离开共享设备前请退出。退出不会取消服务器上已经开始的操作。'),
                    const SizedBox(height: 24),
                    FilledButton.icon(
                      onPressed: busy ? null : () => context.go('/overview'),
                      icon: const Icon(Icons.arrow_forward),
                      label: const Text('进入管理台'),
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton.icon(
                      key: const ValueKey('management-logout'),
                      onPressed: busy ? null : logout,
                      icon: const Icon(Icons.logout),
                      label: const Text('退出管理会话'),
                    ),
                  ] else ...[
                    Form(
                      key: form,
                      child: AutofillGroup(
                        child: Column(
                          children: [
                            TextFormField(
                              controller: username,
                              enabled: !busy && session.canAuthenticate,
                              autofillHints: const [AutofillHints.username],
                              textInputAction: TextInputAction.next,
                              decoration: const InputDecoration(
                                labelText: '管理员用户名',
                              ),
                              validator: (value) => (value ?? '').trim().isEmpty
                                  ? '请输入用户名。'
                                  : null,
                            ),
                            const SizedBox(height: 20),
                            TextFormField(
                              controller: accessToken,
                              enabled: !busy && session.canAuthenticate,
                              obscureText: !visible,
                              autocorrect: false,
                              enableSuggestions: false,
                              decoration: InputDecoration(
                                labelText: '管理访问令牌',
                                suffixIcon: IconButton(
                                  tooltip: visible ? '隐藏令牌' : '显示令牌',
                                  onPressed: busy
                                      ? null
                                      : () =>
                                            setState(() => visible = !visible),
                                  icon: Icon(
                                    visible
                                        ? Icons.visibility_off_outlined
                                        : Icons.visibility_outlined,
                                  ),
                                ),
                              ),
                              onFieldSubmitted: (_) => login(),
                              validator: (value) =>
                                  (value ?? '').isEmpty ? '请输入管理访问令牌。' : null,
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      '使用部署时设置的访问令牌，不是节点连接密码。',
                      style: t.bodySmall?.copyWith(color: c.textSecondary),
                    ),
                    const SizedBox(height: 28),
                    if (busy)
                      const VpLoading(label: '正在联系管理服务…')
                    else
                      FilledButton(
                        key: const ValueKey('management-login'),
                        onPressed: session.canAuthenticate ? login : null,
                        child: const Padding(
                          padding: EdgeInsets.symmetric(vertical: 3),
                          child: Text('登录管理台'),
                        ),
                      ),
                  ],
                  const SizedBox(height: 20),
                  const ExpansionTile(
                    tilePadding: EdgeInsets.zero,
                    title: Text('登录与安全说明'),
                    childrenPadding: EdgeInsets.only(bottom: 16),
                    children: [
                      Text('管理访问令牌与节点连接凭据相互独立。本页不会保存明文令牌，也不会将它发送到其他站点。'),
                      SizedBox(height: 12),
                      Text(
                        '浏览器会话使用 HttpOnly Cookie。CSRF 令牌仅存于内存，刷新后从当前管理服务恢复。第二因素登录尚未开放。',
                      ),
                    ],
                  ),
                ],
              ),
            );
            return SingleChildScrollView(
              keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
              padding: EdgeInsets.all(margin),
              child: ConstrainedBox(
                constraints: BoxConstraints(
                  minHeight: (box.maxHeight - margin * 2).clamp(
                    0,
                    double.infinity,
                  ),
                ),
                child: wide
                    ? IntrinsicHeight(
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Expanded(flex: 5, child: _EntryEditorial()),
                            Expanded(
                              flex: 6,
                              child: Padding(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 56,
                                  vertical: 40,
                                ),
                                child: Center(child: content),
                              ),
                            ),
                          ],
                        ),
                      )
                    : Center(child: content),
              ),
            );
          },
        ),
      ),
    );
  }
}

class _ManagementWordmark extends StatelessWidget {
  const _ManagementWordmark();
  @override
  Widget build(BuildContext context) => Row(
    children: [
      Text(
        'VP',
        style: Theme.of(
          context,
        ).textTheme.headlineMedium?.copyWith(letterSpacing: -1),
      ),
      const SizedBox(width: 16),
      Container(
        height: 20,
        width: 1,
        color: VpColors.of(context).borderControl,
      ),
      const SizedBox(width: 16),
      Text('服务器管理', style: Theme.of(context).textTheme.labelLarge),
    ],
  );
}

class _EntryEditorial extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final t = Theme.of(context).textTheme;
    return Container(
      padding: const EdgeInsets.all(48),
      decoration: BoxDecoration(
        color: c.surfaceSubtle,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _ManagementWordmark(),
          const Spacer(),
          Icon(Icons.hub_outlined, size: 48, color: c.action),
          const SizedBox(height: 32),
          Text(
            '你的服务器，\n一处掌握。',
            style: t.displaySmall?.copyWith(
              fontSize: 44,
              height: 1.38,
              letterSpacing: -1.5,
            ),
          ),
          const SizedBox(height: 24),
          Text(
            '从监听配置到运行状态，\n让每一次变更清楚可见。',
            style: t.bodyLarge?.copyWith(height: 1.8, color: c.textSecondary),
          ),
          const Spacer(),
          const Divider(),
          const SizedBox(height: 20),
          Text(
            '独立部署 · 专属管理入口',
            style: t.labelLarge?.copyWith(color: c.textSecondary),
          ),
          const SizedBox(height: 8),
          Text(
            '此管理台不会接管浏览器所在设备的网络。',
            style: t.bodySmall?.copyWith(color: c.textSecondary),
          ),
        ],
      ),
    );
  }
}

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_design_system/vp_design_system.dart';
import 'common_widgets.dart';
import 'providers.dart';
import 'state.dart';
import 'runtime_notification_settings.dart';
import 'user_dns_settings.dart';

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key});
  @override
  Widget build(BuildContext context) => VpPage(
    eyebrow: '本机设置',
    title: '设置',
    description: '配置 DNS、通知与外观。',
    children: [
      const RuntimeNotificationSettings(),
      const UserDnsSettingsEditor(),
      VpSection(
        title: '外观与可访问性',
        child: Column(
          children: [
            VpKeyValue(
              '主题',
              Theme.of(context).brightness == Brightness.dark
                  ? '深色 · 跟随系统'
                  : '浅色 · 跟随系统',
            ),
            VpKeyValue(
              '高对比',
              MediaQuery.highContrastOf(context) ? '已启用系统高对比模式' : '跟随系统',
            ),
            VpKeyValue(
              '减少动态效果',
              MediaQuery.disableAnimationsOf(context) ? '已启用' : '跟随系统',
            ),
            const Text('手动主题覆盖与设置持久化尚未接入；不会显示已保存但重启即丢失的设置。'),
          ],
        ),
      ),
      VpSection(
        title: '连接与系统',
        child: Column(
          children: [
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('连接诊断'),
              subtitle: const Text('检查真实状态；导出前先查看脱敏内容'),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => context.push('/settings/diagnostics'),
            ),
            const VpNotice(
              title: '断线与系统限制',
              message:
                  '发生错误时会断开 VPN；断开后应用可能恢复直连。此版本未启用始终开启或无 VPN 流量阻断。后台运行仍受系统管理。',
            ),
          ],
        ),
      ),
      const VpSection(
        title: '关于此开发版本',
        child: Text('开发测试版本，尚未完成全部平台验收。协议支持以实际验证结果为准。'),
      ),
    ],
  );
}

class DiagnosticsPage extends ConsumerStatefulWidget {
  const DiagnosticsPage({super.key, this.admin = false});
  final bool admin;
  @override
  ConsumerState<DiagnosticsPage> createState() => _DiagnosticsPageState();
}

class _DiagnosticsPageState extends ConsumerState<DiagnosticsPage> {
  LoadState<DiagnosticReport>? state;
  Future<void> inspect() async {
    if (state is Loading<DiagnosticReport>) return;
    final old = state?.previous;
    setState(() => state = Loading(old));
    try {
      final report = await ref.read(diagnosticsProvider).inspect();
      if (mounted) setState(() => state = Loaded(report));
    } catch (error) {
      if (mounted) setState(() => state = LoadFailed(safeFailure(error), old));
    }
  }

  @override
  Widget build(BuildContext context) {
    final report = state?.previous;
    return VpPage(
      eyebrow: widget.admin ? '服务器诊断' : '本机诊断',
      title: '找到问题，不暴露秘密',
      description: '检查按权限、系统接管、隧道、转发和 DNS 分层呈现。尚未运行的检查不会显示正常。',
      action: FilledButton.icon(
        onPressed: state is Loading<DiagnosticReport> ? null : inspect,
        icon: const Icon(Icons.fact_check_outlined),
        label: const Text('运行诊断'),
      ),
      children: [
        if (state == null)
          const VpEmpty(title: '尚未运行诊断', message: '不会自动收集浏览内容、完整 URL、口令或私钥。')
        else
          LoadNotice(state!, retry: inspect),
        if (report != null) ...[
          VpSection(
            title: '检查结果',
            child: Column(
              children: [
                VpKeyValue('检查时间', formatMoment(report.generatedAt)),
                VpKeyValue('产品版本', report.productVersion),
                VpKeyValue('核心身份', report.coreIdentity),
                for (final check in report.checks)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    title: Text(check.label),
                    subtitle: Text(check.detail),
                    leading: Icon(
                      check.state == EvidenceState.passed
                          ? Icons.check_circle_outline
                          : check.state == EvidenceState.failed
                          ? Icons.error_outline
                          : Icons.help_outline,
                    ),
                  ),
              ],
            ),
          ),
          VpSection(
            title: '脱敏日志预览',
            description: '可能仍包含 IP、域名或节点元数据；分享前请检查。',
            child: SelectableText(
              report.redactedLines.isEmpty
                  ? '没有可显示的日志。'
                  : report.redactedLines.join('\n'),
            ),
          ),
          const VpNotice(
            title: '导出尚未接入',
            message: '只有经过脱敏验证与用户确认的诊断包才能下载；不会生成假空包。',
          ),
        ],
      ],
    );
  }
}

class PendingFeaturePage extends StatelessWidget {
  const PendingFeaturePage({
    super.key,
    required this.title,
    required this.description,
  });
  final String title, description;
  @override
  Widget build(BuildContext context) => VpPage(
    eyebrow: '服务器管理',
    title: title,
    description: description,
    children: const [
      VpNotice(
        title: '该功能尚未实现',
        message: '当前源代码阶段没有可用的业务适配器和完整交互。该项仍是发布阻断，不会用静态卡片或成功提示冒充已完成。',
        tone: VpTone.warning,
      ),
    ],
  );
}

class MaintenancePage extends ConsumerWidget {
  const MaintenancePage({super.key});
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final controller = ref.watch(adminProvider);
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) => VpPage(
        eyebrow: '服务器维护',
        title: '每次变更都有来路',
        description: '提交后可通过操作编号找回进度。更新、回滚与卸载不能通过替换任意二进制执行。',
        children: [
          LoadNotice(controller.state, retry: controller.refresh),
          if (controller.plan != null)
            OutlinedButton(
              onPressed: () => context.go('/maintenance/plan'),
              child: const Text('继续核对变更计划'),
            ),
          if (controller.state.previous != null)
            VpSection(
              title: '操作记录',
              child: Column(
                children: [
                  if (controller.state.previous!.operations.isEmpty)
                    const Text('尚无服务端操作记录。'),
                  for (final operation in controller.state.previous!.operations)
                    ListTile(
                      title: Text('${operation.status} · ${operation.stage}'),
                      subtitle: Text(operation.id),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => context.go(
                        '/maintenance/operations/${Uri.encodeComponent(operation.id)}',
                      ),
                    ),
                ],
              ),
            ),
          const VpNotice(
            title: '升级与恢复流程尚未接入',
            message: '版本签名、兼容性、备份、升级计划与失败恢复仍需实现和验证。当前不能执行升级、卸载或任意系统命令。',
            tone: VpTone.warning,
          ),
        ],
      ),
    );
  }
}

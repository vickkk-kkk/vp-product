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

String connectionLabel(ConnectionPhase phase) => switch (phase) {
  ConnectionPhase.unavailable => '运行组件不可用',
  ConnectionPhase.unconfigured => '还没有可用节点',
  ConnectionPhase.disconnected => '未连接',
  ConnectionPhase.awaitingPermission => '等待系统授权',
  ConnectionPhase.preparing => '正在检查配置',
  ConnectionPhase.starting => '正在建立连接',
  ConnectionPhase.verifying => '正在验证连接',
  ConnectionPhase.enabledUnverified => '运行中，待验证',
  ConnectionPhase.verified => '已连接',
  ConnectionPhase.degraded => '连接受限',
  ConnectionPhase.reconnecting => '正在恢复连接',
  ConnectionPhase.stopping => '正在断开',
  ConnectionPhase.recovering => '正在恢复系统设置',
  ConnectionPhase.failed => '连接未完成',
  ConnectionPhase.recoveryRequired => '系统设置需要恢复',
};

class ConnectionPage extends ConsumerStatefulWidget {
  const ConnectionPage({super.key});
  @override
  ConsumerState<ConnectionPage> createState() => _ConnectionPageState();
}

class _ConnectionPageState extends ConsumerState<ConnectionPage>
    with WidgetsBindingObserver {
  bool _confirmingDevelopment = false;
  late final ConnectionController _observations;
  bool _foreground = true;
  @override
  void initState() {
    super.initState();
    _observations = ref.read(connectionProvider);
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    final visible = ModalRoute.isCurrentOf(context) ?? true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _observations.setObservationActive(_foreground && visible);
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _foreground = state == AppLifecycleState.resumed;
    if (mounted)
      _observations.setObservationActive(
        _foreground && (ModalRoute.of(context)?.isCurrent ?? true),
      );
  }

  @override
  void dispose() {
    _observations.setObservationActive(false);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _developmentConnect(NodeView node, String revision) async {
    if (_confirmingDevelopment) return;
    setState(() => _confirmingDevelopment = true);
    try {
      final confirmed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('仅限未认证开发测试'),
          content: const Text(
            '此连接方式尚未完成平台验收。仅在受控测试环境使用，不代表可发布或已验证；仍须通过真实内核校验和系统 VPN 授权。',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('确认测试连接'),
            ),
          ],
        ),
      );
      if (!mounted || confirmed != true) return;
      final inventory = ref.read(inventoryProvider).state;
      if (inventory is! Loaded<Revisioned<ClientInventory>> ||
          inventory.value.revision != revision ||
          inventory.value.value.selectedNodeId != node.id)
        return;
      await ref
          .read(connectionProvider)
          .connectNode(
            node: node,
            inventoryRevision: revision,
            development: true,
          );
    } finally {
      if (mounted) setState(() => _confirmingDevelopment = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final connection = ref.watch(connectionProvider);
    final inventory = ref.watch(inventoryProvider);
    return ListenableBuilder(
      listenable: Listenable.merge([connection, inventory]),
      builder: (context, _) {
        final snapshot = connection.state.previous;
        final readError = switch (connection.state) {
          LoadFailed(:final error) => error,
          _ => null,
        };
        final runtimeMissing = readError?.code == 'RUNTIME_UNAVAILABLE';
        final current = inventory.state.previous?.value.selectedNode;
        final stale =
            snapshot == null ||
            snapshot.isStale(DateTime.now()) ||
            connection.state is! Loaded<ConnectionView>;
        final ready = !stale && !connection.mutation.blocked;
        final uncertain = connection.mutation is MutationUncertain;
        final verified = !stale && snapshot.isVerified && !uncertain;
        final disconnect = snapshot?.canDisconnect == true;
        final developing =
            current != null &&
            developmentConnectionEligible(current.capability);
        final inventoryReady =
            inventory.state is Loaded<Revisioned<ClientInventory>>;
        final empty =
            inventoryReady &&
            current == null &&
            inventory.state.previous!.value.nodes.isEmpty &&
            !disconnect;
        final canConnect =
            ready &&
            snapshot.canConnect &&
            inventoryReady &&
            current != null &&
            (current.capability.runnable || developing);
        final status = uncertain
            ? '结果待确认'
            : empty && !stale
            ? '从你的节点开始'
            : runtimeMissing
            ? '连接暂不可用'
            : snapshot == null
            ? (connection.state is Loading<ConnectionView>
                  ? '正在读取状态'
                  : '状态暂不可用')
            : stale
            ? '状态待刷新'
            : snapshot.phase == ConnectionPhase.verified && !snapshot.isVerified
            ? '已启用，尚未验证'
            : connectionLabel(snapshot.phase);
        final explanation = uncertain
            ? '先查询原操作，避免重复连接'
            : empty && !stale
            ? '自己的服务器，也可以轻松接入'
            : runtimeMissing
            ? '此版本尚未提供本机连接组件。'
            : readError?.message ??
                  (stale
                      ? '正在确认本机的连接状态'
                      : verified
                      ? '已通过连接检查'
                      : current == null
                      ? '添加你的节点，开始连接'
                      : developing && !disconnect
                      ? '当前节点仅可用于未认证开发测试'
                      : !disconnect && !current.capability.runnable
                      ? '此节点暂不可连接，可在详情中查看原因'
                      : snapshot.phase == ConnectionPhase.disconnected
                      ? '准备就绪，由你决定何时连接'
                      : snapshot.summary);
        final action = empty
            ? '添加节点'
            : disconnect
            ? '断开连接'
            : developing
            ? '测试连接'
            : '连接';
        final waitingForPermission =
            !stale && snapshot.phase == ConnectionPhase.awaitingPermission;
        final busy =
            connection.mutation is MutationRunning ||
            !stale &&
                const {
                  ConnectionPhase.preparing,
                  ConnectionPhase.starting,
                  ConnectionPhase.verifying,
                  ConnectionPhase.reconnecting,
                  ConnectionPhase.stopping,
                  ConnectionPhase.recovering,
                }.contains(snapshot.phase);
        final attention =
            uncertain ||
            !stale &&
                const {
                  ConnectionPhase.degraded,
                  ConnectionPhase.failed,
                  ConnectionPhase.recoveryRequired,
                }.contains(snapshot.phase);
        final controlLabel = waitingForPermission
            ? '等待授权'
            : connection.mutation is MutationRunning
            ? '处理中'
            : action;
        void connect() {
          if (current == null) return;
          if (developing) {
            unawaited(
              _developmentConnect(current, inventory.state.previous!.revision),
            );
          } else {
            unawaited(
              connection.connectNode(
                node: current,
                inventoryRevision: inventory.state.previous!.revision,
              ),
            );
          }
        }

        void stop() => unawaited(
          connection.command(
            '正在请求断开',
            (identity) => connection.runtime.disconnect(
              expectedInstanceId: snapshot!.instanceId,
              expectedGeneration: snapshot.generation,
              command: identity,
            ),
          ),
        );
        final onPress = empty
            ? () => context.push('/import')
            : disconnect
            ? (ready ? stop : null)
            : (canConnect && !_confirmingDevelopment ? connect : null);
        return LayoutBuilder(
          builder: (context, constraints) {
            final compact =
                constraints.maxHeight < 560 || constraints.maxWidth < 360;
            final inset = constraints.maxWidth < 360 ? 20.0 : 24.0;
            return SafeArea(
              top: false,
              bottom: false,
              child: Align(
                alignment: Alignment.topCenter,
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 560),
                  child: SingleChildScrollView(
                    key: const PageStorageKey('connection-home'),
                    child: ConstrainedBox(
                      constraints: BoxConstraints(
                        minHeight: constraints.maxHeight,
                      ),
                      child: IntrinsicHeight(
                        child: Padding(
                          padding: EdgeInsets.fromLTRB(inset, 12, inset, 12),
                          child: Column(
                            children: [
                              Expanded(
                                child: Center(
                                  child: Padding(
                                    padding: EdgeInsets.symmetric(
                                      vertical: compact ? 12 : 28,
                                    ),
                                    child: Column(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        VpConnectionControl(
                                          key: const ValueKey('connect-node'),
                                          label: controlLabel,
                                          icon: empty
                                              ? Icons.add_rounded
                                              : Icons
                                                    .power_settings_new_rounded,
                                          onPressed: onPress,
                                          verified: verified,
                                          busy: busy,
                                          waitingForPermission:
                                              waitingForPermission,
                                          attention: attention,
                                          compact: compact,
                                        ),
                                        SizedBox(height: compact ? 20 : 26),
                                        Semantics(
                                          liveRegion: true,
                                          child: AnimatedSwitcher(
                                            duration:
                                                MediaQuery.disableAnimationsOf(
                                                  context,
                                                )
                                                ? Duration.zero
                                                : const Duration(
                                                    milliseconds: 180,
                                                  ),
                                            child: Text(
                                              status,
                                              key: ValueKey(status),
                                              textAlign: TextAlign.center,
                                              style: Theme.of(context)
                                                  .textTheme
                                                  .headlineLarge
                                                  ?.copyWith(
                                                    fontWeight: FontWeight.w500,
                                                    fontVariations: const [
                                                      FontVariation(
                                                        'wght',
                                                        500,
                                                      ),
                                                    ],
                                                    color: VpColors.of(
                                                      context,
                                                    ).textPrimary,
                                                  ),
                                            ),
                                          ),
                                        ),
                                        const SizedBox(height: 8),
                                        Text(
                                          explanation,
                                          textAlign: TextAlign.center,
                                          style: Theme.of(context)
                                              .textTheme
                                              .bodySmall
                                              ?.copyWith(
                                                color: VpColors.of(
                                                  context,
                                                ).textSecondary,
                                              ),
                                        ),
                                        if (snapshot?.canCancel == true &&
                                            snapshot?.operationId != null)
                                          TextButton(
                                            onPressed: ready
                                                ? () => connection.command(
                                                    '正在请求取消',
                                                    (identity) => connection
                                                        .runtime
                                                        .cancel(
                                                          expectedInstanceId:
                                                              snapshot
                                                                  .instanceId,
                                                          operationId: snapshot
                                                              .operationId!,
                                                          command: identity,
                                                        ),
                                                  )
                                                : null,
                                            child: const Text('取消连接'),
                                          ),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                              if (connection.mutation is MutationUncertain ||
                                  connection.mutation is MutationFailed) ...[
                                MutationNotice(
                                  connection.mutation,
                                  onReconcile: connection.reconcile,
                                ),
                                const SizedBox(height: 16),
                              ],
                              if (empty)
                                const _EmptyNodeGuide()
                              else
                                _NodeAnchor(
                                  key: const ValueKey(
                                    'connection-node-selector',
                                  ),
                                  node: current,
                                  inventoryReady: inventoryReady,
                                  nextConnection:
                                      snapshot?.nodeId != null &&
                                      snapshot?.nodeId != current?.id,
                                  onTap: () =>
                                      current == null &&
                                          inventoryReady &&
                                          inventory
                                              .state
                                              .previous!
                                              .value
                                              .nodes
                                              .isEmpty
                                      ? context.push('/import')
                                      : context.go('/nodes'),
                                ),
                              const SizedBox(height: 4),
                              TextButton(
                                key: const ValueKey('connection-details'),
                                onPressed: () => _showDetails(
                                  connection,
                                  current,
                                  readError,
                                  snapshot,
                                ),
                                style: TextButton.styleFrom(
                                  foregroundColor: VpColors.of(
                                    context,
                                  ).textSecondary,
                                ),
                                child: const Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Text('连接详情'),
                                    SizedBox(width: 4),
                                    Icon(Icons.arrow_forward_rounded, size: 16),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            );
          },
        );
      },
    );
  }

  Future<void> _showDetails(
    ConnectionController controller,
    NodeView? node,
    ProductFailure? error,
    ConnectionView? snapshot,
  ) => showModalBottomSheet<void>(
    context: context,
    isScrollControlled: true,
    useSafeArea: true,
    showDragHandle: true,
    builder: (context) => DraggableScrollableSheet(
      expand: false,
      initialChildSize: .64,
      minChildSize: .4,
      maxChildSize: .92,
      builder: (context, scroll) => ListView(
        controller: scroll,
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
        children: [
          Text('连接详情', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 20),
          if (error != null) ...[
            Text(error.message),
            const SizedBox(height: 8),
            Text(error.remediation ?? ''),
            VpKeyValue('诊断代码', error.code),
          ],
          if (snapshot != null) ...[
            VpKeyValue('最近读取', formatMoment(snapshot.observedAt)),
            VpKeyValue('配置修订', snapshot.revision ?? '尚无记录'),
            if (snapshot.nodeId != null && snapshot.nodeId != node?.id)
              VpKeyValue('正在使用的节点 ID', snapshot.nodeId!),
            for (final evidence in snapshot.evidence)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  evidence.state == EvidenceState.passed
                      ? Icons.check_circle_outline
                      : evidence.state == EvidenceState.failed
                      ? Icons.error_outline
                      : Icons.circle_outlined,
                ),
                title: Text(evidence.label),
                subtitle: Text(evidence.detail),
              ),
          ],
          if (node != null) ...[
            const SizedBox(height: 12),
            CapabilityNote(node.capability),
          ],
          if (error?.code != 'RUNTIME_UNAVAILABLE')
            TextButton.icon(
              onPressed: () {
                Navigator.pop(context);
                unawaited(controller.refresh());
              },
              icon: const Icon(Icons.refresh),
              label: const Text('刷新状态'),
            ),
          if (snapshot?.phase == ConnectionPhase.degraded ||
              snapshot?.phase == ConnectionPhase.failed)
            OutlinedButton(
              onPressed: () {
                Navigator.pop(context);
                this.context.push('/settings/diagnostics');
              },
              child: const Text('检查连接问题'),
            ),
        ],
      ),
    ),
  );
}

class _NodeAnchor extends StatelessWidget {
  const _NodeAnchor({
    super.key,
    required this.node,
    required this.inventoryReady,
    required this.nextConnection,
    required this.onTap,
  });
  final NodeView? node;
  final bool inventoryReady, nextConnection;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    final title = node?.name ?? (inventoryReady ? '添加你的节点' : '节点信息暂不可用');
    final detail = node == null
        ? (inventoryReady ? '支持自己的服务器与订阅' : '打开节点查看详情')
        : '${node!.protocolLabel} · ${node!.transportLabel}';
    return Semantics(
      label: '${nextConnection ? '下次连接节点' : '当前节点'}，$title，$detail',
      button: true,
      onTap: onTap,
      child: ExcludeSemantics(
        child: Material(
          color: c.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: c.borderSubtle),
          ),
          child: InkWell(
            onTap: onTap,
            borderRadius: BorderRadius.circular(20),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 17),
              child: Row(
                children: [
                  Container(
                    width: 42,
                    height: 42,
                    decoration: BoxDecoration(
                      color: c.surfaceSubtle,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Icon(
                      node == null ? Icons.add_rounded : Icons.dns_outlined,
                      size: 21,
                      color: c.textSecondary,
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (nextConnection)
                          Text(
                            '下次连接',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        Text(
                          title,
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 4),
                        Text(
                          detail,
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(color: c.textSecondary),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  Icon(
                    Icons.chevron_right_rounded,
                    color: c.textTertiary,
                    size: 22,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _EmptyNodeGuide extends StatelessWidget {
  const _EmptyNodeGuide();
  @override
  Widget build(BuildContext context) {
    final c = VpColors.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 18),
      child: Wrap(
        alignment: WrapAlignment.center,
        spacing: 24,
        runSpacing: 12,
        children: [
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.link_rounded, size: 18, color: c.textTertiary),
              const SizedBox(width: 8),
              Text(
                '节点链接',
                style: Theme.of(
                  context,
                ).textTheme.bodySmall?.copyWith(color: c.textSecondary),
              ),
            ],
          ),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.dynamic_feed_outlined,
                size: 18,
                color: c.textTertiary,
              ),
              const SizedBox(width: 8),
              Text(
                '订阅地址',
                style: Theme.of(
                  context,
                ).textTheme.bodySmall?.copyWith(color: c.textSecondary),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

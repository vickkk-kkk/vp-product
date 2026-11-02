import '../vp_contracts.dart'
    show
        ConnectionView,
        ConnectionPhase,
        EvidenceView,
        EvidenceState,
        ProductFailure;

/// Hand-authored, read-only consumer of crates/vp-domain/src/runtime.rs.
/// Not generated. No toJson/save: unknown/future data can never be overwritten.
/// Code generation/drift verification remains a build gate.
class RuntimeSnapshotDto {
  const RuntimeSnapshotDto({
    required this.instanceId,
    required this.generation,
    required this.sequence,
    required this.observedAt,
    required this.validUntil,
    required this.desiredNodeId,
    required this.phase,
    required this.configRevision,
    required this.nodeId,
    required this.operationId,
    required this.health,
    required this.desiredRevision,
    required this.requiredProbes,
  });
  final String instanceId, phase;
  final int generation, sequence;
  final DateTime observedAt, validUntil;
  final String? desiredNodeId, nodeId, operationId;
  final int? configRevision, desiredRevision;
  final Set<String> requiredProbes;
  final Map<String, HealthObservationDto> health;

  factory RuntimeSnapshotDto.fromJson(Map<String, Object?> json) {
    if (_integer(json, 'schemaVersion') != 1) throw _incompatible;
    final intent = _object(json['desired']);
    final kind = _string(intent, 'kind');
    if (kind != 'connected' && kind != 'disconnected') throw _incompatible;
    final phase = _string(json, 'phase');
    if (!const {
      'idle',
      'preparing',
      'awaiting_permission',
      'starting',
      'verifying',
      'connected',
      'degraded',
      'reconnecting',
      'stopping',
      'failed',
      'recovering',
    }.contains(phase))
      throw _incompatible;
    final health = _object(json['health']);
    final probes = health['requiredProbes'];
    if (probes is! List<Object?> ||
        probes.any(
          (value) => !const {
            'core',
            'takeover',
            'tunnel',
            'dns',
            'ipv4',
            'ipv6',
            'forwarding',
          }.contains(value),
        ))
      throw _incompatible;
    return RuntimeSnapshotDto(
      instanceId: _string(json, 'instanceId'),
      generation: _integer(json, 'generation'),
      sequence: _integer(json, 'sequence'),
      observedAt: _timestamp(json, 'observedAt'),
      validUntil: _timestamp(json, 'validUntil'),
      desiredNodeId: kind == 'connected' ? _id(intent, 'nodeId') : null,
      phase: phase,
      configRevision: json['configRevision'] == null
          ? null
          : _integer(json, 'configRevision'),
      desiredRevision: json['desiredRevision'] == null
          ? null
          : _integer(json, 'desiredRevision'),
      requiredProbes: Set.unmodifiable(probes.cast<String>()),
      nodeId: _optionalId(json, 'nodeId'),
      operationId: _optionalId(json, 'operationId'),
      health: Map.unmodifiable({
        for (final key in const [
          'core',
          'takeover',
          'tunnel',
          'dns',
          'ipv4',
          'ipv6',
          'forwarding',
        ])
          key: HealthObservationDto.fromJson(_object(health[key])),
      }),
    );
  }
  bool isFresh(DateTime now) =>
      !now.isBefore(observedAt) && now.isBefore(validUntil);
  Set<String> get allRequired => {
    'core',
    'takeover',
    'tunnel',
    'forwarding',
    ...requiredProbes,
  };
  bool connectionVerifiedAt(DateTime now) {
    if (!isFresh(now) ||
        phase != 'connected' ||
        desiredNodeId == null ||
        desiredNodeId != nodeId ||
        desiredRevision == null ||
        desiredRevision != configRevision)
      return false;
    final validity = validUntil.difference(observedAt);
    return allRequired.every((key) {
      final observation = health[key]!;
      final at = observation.observedAt;
      return observation.status == 'passed' &&
          observation.evidenceId != null &&
          at != null &&
          !at.isAfter(observedAt) &&
          observedAt.difference(at) <= validity;
    });
  }

  ConnectionView toView({DateTime? now}) {
    final currentTime = now ?? DateTime.now();
    final failures = health.entries
        .where((entry) => entry.value.status == 'failed')
        .map((entry) => _healthLabel(entry.key))
        .toList();
    final verified = connectionVerifiedAt(currentTime);
    final mapped = switch (phase) {
      'idle' => ConnectionPhase.disconnected,
      'preparing' => ConnectionPhase.preparing,
      'awaiting_permission' => ConnectionPhase.awaitingPermission,
      'starting' => ConnectionPhase.starting,
      'verifying' => ConnectionPhase.verifying,
      'connected' =>
        failures.isNotEmpty
            ? ConnectionPhase.degraded
            : verified
            ? ConnectionPhase.verified
            : ConnectionPhase.enabledUnverified,
      'degraded' => ConnectionPhase.degraded,
      'reconnecting' => ConnectionPhase.reconnecting,
      'stopping' => ConnectionPhase.stopping,
      'recovering' => ConnectionPhase.recovering,
      _ => ConnectionPhase.failed,
    };
    return ConnectionView(
      instanceId: instanceId,
      generation: generation,
      sequence: sequence,
      phase: mapped,
      observedAt: observedAt,
      validUntil: validUntil,
      nodeId: nodeId,
      revision: configRevision?.toString(),
      operationId: operationId,
      summary: failures.isNotEmpty
          ? '${failures.join('、')}检查未通过。'
          : verified
          ? '系统接管、隧道与所需路径已验证。验证范围与时间可在连接详情查看。'
          : phase == 'connected'
          ? '运行组件已启用，尚未取得完整的连接验证结果。'
          : '状态由本机运行组件提供。',
      // Permission/action policy is a separate host responsibility; idle alone
      // cannot grant a connection action. A verified host adapter composes it.
      canConnect: false,
      canDisconnect: phase != 'idle' && phase != 'stopping',
      canCancel: false,
      evidence: [
        for (final entry in health.entries)
          EvidenceView(
            label: _healthLabel(entry.key),
            state: switch (entry.value.status) {
              'passed' => EvidenceState.passed,
              'failed' => EvidenceState.failed,
              'not_applicable' => EvidenceState.notApplicable,
              _ => EvidenceState.unknown,
            },
            detail: entry.value.detailKey ?? '尚无详细说明',
            observedAt: entry.value.observedAt,
            requiredForConnection: allRequired.contains(entry.key),
          ),
      ],
    );
  }
}

class HealthObservationDto {
  const HealthObservationDto(
    this.status,
    this.observedAt,
    this.evidenceId,
    this.detailKey,
  );
  final String status;
  final DateTime? observedAt;
  final String? evidenceId, detailKey;
  factory HealthObservationDto.fromJson(Map<String, Object?> json) {
    final status = _string(json, 'status');
    if (!const {
      'not_run',
      'passed',
      'failed',
      'not_applicable',
    }.contains(status))
      throw _incompatible;
    final detail = _optionalString(json, 'detailKey');
    if (detail != null && !RegExp(r'^[A-Za-z0-9._-]{1,128}$').hasMatch(detail))
      throw _incompatible;
    return HealthObservationDto(
      status,
      json['observedAt'] == null ? null : _timestamp(json, 'observedAt'),
      _optionalId(json, 'evidenceId'),
      detail,
    );
  }
}

const _incompatible = ProductFailure(
  'CONTRACT_INCOMPATIBLE',
  '运行组件返回了无法安全读取的状态。',
  remediation: '保持只读并检查产品与运行组件版本，不要通过忽略字段继续操作。',
);
Map<String, Object?> _object(Object? value) {
  if (value is! Map<String, Object?>) throw _incompatible;
  return value;
}

String _string(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! String || value.isEmpty || value.length > 512)
    throw _incompatible;
  return value;
}

String? _optionalString(Map<String, Object?> json, String key) =>
    json[key] == null ? null : _string(json, key);
int _integer(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! int || value < 0 || value > 9007199254740991)
    throw _incompatible;
  return value;
}

DateTime _timestamp(Map<String, Object?> json, String key) {
  final value = _integer(json, key);
  if (value > 8640000000000000) throw _incompatible;
  return DateTime.fromMillisecondsSinceEpoch(value, isUtc: true);
}

String _healthLabel(String key) => switch (key) {
  'core' => '运行组件',
  'takeover' => '系统网络接管',
  'tunnel' => '隧道',
  'dns' => 'DNS',
  'ipv4' => 'IPv4',
  'ipv6' => 'IPv6',
  'forwarding' => '实际转发',
  _ => '未知检查',
};

String _id(Map<String, Object?> json, String key) {
  final value = _string(json, key);
  if (!RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(value)) throw _incompatible;
  return value;
}

String? _optionalId(Map<String, Object?> json, String key) =>
    json[key] == null ? null : _id(json, key);

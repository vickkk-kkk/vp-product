import 'package:vp_contracts/vp_contracts.dart';

const malformed = ProductFailure(
  'CONTRACT_INCOMPATIBLE',
  '管理服务返回了无法安全读取的数据。',
  remediation: '请检查 Web 与管理服务版本。不会忽略必需字段或猜测运行状态。',
);
Map<String, Object?> object(Object? value) {
  if (value is! Map<String, Object?>) throw malformed;
  return value;
}

List<Object?> array(Object? value) {
  if (value is! List<Object?>) throw malformed;
  return value;
}

String string(Object? value, {int max = 4096}) {
  if (value is! String ||
      value.isEmpty ||
      value.length > max ||
      value.contains('\u0000'))
    throw malformed;
  return value;
}

String id(Object? value) {
  final result = string(value, max: 128);
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(result)) throw malformed;
  return result;
}

String code(Object? value) {
  final result = string(value, max: 128);
  if (!RegExp(r'^[A-Za-z0-9._-]+$').hasMatch(result)) throw malformed;
  return result;
}

int revision(Object? value) {
  if (value is! int || value < 0 || value > 9007199254740991) throw malformed;
  return value;
}

bool boolean(Object? value) {
  if (value is! bool) throw malformed;
  return value;
}

void schema(Map<String, Object?> value) {
  if (value['schemaVersion'] != 1) throw malformed;
}

ProductFailure productError(Object? value, {required bool mutation}) {
  final json = object(value);
  final errorCode = code(json['code']);
  // Only a validated rejection response for these stages proves non-application.
  final stage = code(json['stage']);
  final rejected =
      !mutation ||
      const {'decode', 'validate', 'authenticate', 'plan'}.contains(stage);
  final message = switch (errorCode) {
    'AUTH_REQUIRED' => '管理会话已失效，请重新登录。',
    'AUTH_FAILED' => '登录失败，请检查凭据。',
    'PERMISSION_DENIED' => '当前会话没有此操作的权限。',
    'REVISION_CONFLICT' => '配置已被其他操作修改，请刷新后重新预览。',
    'CAPABILITY_UNCERTIFIED' => '该协议组合尚未通过认证，不能应用。',
    'CAPABILITY_UNAVAILABLE' => '所需运行能力尚未接入。',
    'CONFIG_INVALID' => '配置校验未通过，请检查字段。',
    'CONFIG_UNKNOWN_FIELD' => '包含当前版本不支持的配置字段。',
    'PLAN_EXPIRED' => '计划已过期，请重新生成。',
    'OPERATION_NOT_CANCELABLE' => '操作已越过可取消阶段。',
    'SECRET_RESULT_UNAVAILABLE' =>
      '此链接可能已签发，但原始链接无法再次读取。请读取安全状态，再明确选择轮换；轮换会使之前链接失效。',
    'EXPORT_LOSSY' => '当前来源无法无损发布，未输出部分订阅。',
    'IDEMPOTENCY_CONFLICT' => '同一操作标识对应了不同请求，已阻止提交。',
    _ => '服务器未完成此操作。',
  };
  final diagnostic = json['diagnosticId'] == null
      ? null
      : id(json['diagnosticId']);
  return ProductFailure(
    errorCode,
    message,
    remediation: '错误阶段：$stage。请保留原操作编号并检查诊断信息。',
    diagnosticId: diagnostic,
    retryable: json['retryable'] == true,
    definitelyNotApplied: rejected && errorCode != 'SECRET_RESULT_UNAVAILABLE',
    outcomeUnknown:
        mutation && (!rejected || errorCode == 'SECRET_RESULT_UNAVAILABLE'),
  );
}

OperationView operation(Object? value) {
  final json = object(value);
  final status = code(json['status']);
  if (!const {
    'queued',
    'running',
    'awaiting_confirmation',
    'succeeded',
    'failed',
    'canceled',
    'rolling_back',
    'rolled_back',
    'recovery_required',
  }.contains(status))
    throw malformed;
  final stage = code(json['stage']);
  final completed = revision(json['completedSteps']);
  final total = revision(json['totalSteps']);
  if (completed > total) throw malformed;
  return OperationView(
    id: id(json['id']),
    stage: _stage(stage),
    status: _status(status),
    lastMessage: '服务端记录：已完成 $completed / $total 个步骤。',
    cancellable: boolean(json['cancellable']),
    terminal: const {
      'succeeded',
      'failed',
      'canceled',
      'rolled_back',
      'recovery_required',
    }.contains(status),
    error: json['error'] == null
        ? null
        : productError(json['error'], mutation: false),
  );
}

String _stage(String value) => switch (value) {
  'validate' => '校验',
  'stage' => '准备配置',
  'stop_old' => '停止旧实例',
  'start_new' => '启动新实例',
  'verify' => '验证运行结果',
  'commit' => '提交修订',
  'rollback' => '回滚',
  'recover' => '恢复',
  _ => throw malformed,
};
String _status(String value) => switch (value) {
  'queued' => '排队中',
  'running' => '进行中',
  'awaiting_confirmation' => '等待确认',
  'succeeded' => '操作成功',
  'failed' => '操作失败',
  'canceled' => '已取消',
  'rolling_back' => '正在回滚',
  'rolled_back' => '已回滚',
  'recovery_required' => '需要恢复',
  _ => throw malformed,
};

String hash(Object? value) {
  final result = string(value, max: 64);
  if (!RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(result)) throw malformed;
  return result;
}

int port(Object? value) {
  final result = revision(value);
  if (result == 0 || result > 65535) throw malformed;
  return result;
}

int timestamp(Object? value) {
  final result = revision(value);
  if (result > 8640000000000000) throw malformed;
  return result;
}

import 'package:vp_contracts/vp_contracts.dart';

export 'package:vp_contracts/vp_contracts.dart'
    show RuntimeControl, RuntimeEvent;

const runtimeUnavailable = ProductFailure(
  'RUNTIME_UNAVAILABLE',
  '本机运行组件尚未接入。',
  remediation: '当前无法接管系统网络或建立连接。安装并验证对应平台组件后，再重新读取状态。',
  retryable: true,
  definitelyNotApplied: true,
);
const storageUnavailable = ProductFailure(
  'STORAGE_UNAVAILABLE',
  '安全的本地节点存储尚未接入。',
  remediation: '不会将节点或订阅凭据保存在临时内存、日志或浏览器存储中。',
  retryable: true,
  definitelyNotApplied: true,
);
const codecUnavailable = ProductFailure(
  'CODEC_UNAVAILABLE',
  '权威导入解析组件尚未接入。',
  remediation: '输入不会发送到第三方，也不会由界面猜测协议参数。',
  retryable: true,
  definitelyNotApplied: true,
);

/// Deliberately no development fixture fallback in production composition.
class UnavailableRuntime implements RuntimeControl {
  const UnavailableRuntime();
  @override
  Future<ConnectionView> snapshot() async => throw runtimeUnavailable;
  @override
  Stream<RuntimeEvent> events({required int afterSequence}) =>
      const Stream.empty();
  @override
  Future<String> connect({
    required String nodeId,
    required MutationIdentity command,
  }) async => throw runtimeUnavailable;
  @override
  Future<String> disconnect({
    required String expectedInstanceId,
    required int expectedGeneration,
    required MutationIdentity command,
  }) async => throw runtimeUnavailable;
  @override
  Future<String> cancel({
    required String expectedInstanceId,
    required String operationId,
    required MutationIdentity command,
  }) async => throw runtimeUnavailable;
  @override
  Future<String?> reconcile(String idempotencyKey) async =>
      throw runtimeUnavailable;
  @override
  Future<void> dispose() async {}
}

class UnavailableClientRepository implements ClientRepository {
  const UnavailableClientRepository();
  @override
  Future<Revisioned<ClientInventory>> read() async => throw storageUnavailable;
  @override
  Future<MutationReceipt> renameNode(
    String id,
    String name,
    MutationIdentity command,
  ) async => throw storageUnavailable;
  @override
  Future<MutationReceipt> selectNode(
    String id,
    MutationIdentity command,
  ) async => throw storageUnavailable;
  @override
  Future<MutationReceipt> deleteNodes(
    Set<String> ids,
    MutationIdentity command,
  ) async => throw storageUnavailable;
  @override
  Future<MutationReceipt> saveSubscription({
    String? id,
    required String name,
    String? replacementUrl,
    required MutationIdentity command,
  }) async => throw storageUnavailable;
  @override
  Future<MutationReceipt> deleteSubscription(
    String id,
    MutationIdentity command,
  ) async => throw storageUnavailable;
  @override
  Future<ImportPreview> previewSubscriptionRefresh(String id) async =>
      throw storageUnavailable;
  @override
  Future<MutationReceipt?> reconcile(String idempotencyKey) async =>
      throw storageUnavailable;
}

class UnavailableImportService implements ImportService {
  const UnavailableImportService();
  @override
  Future<ImportPreview> previewText(
    String text,
    String expectedRevision,
  ) async => throw codecUnavailable;
  @override
  Future<ImportCommit> commit(
    ImportPreview preview,
    ImportSelection selection,
    MutationIdentity command,
  ) async => throw codecUnavailable;
  @override
  Future<ImportCommit?> reconcile(String idempotencyKey) async =>
      throw codecUnavailable;
}

class UnavailableDiagnostics implements DiagnosticsService {
  const UnavailableDiagnostics();
  @override
  Future<DiagnosticReport> inspect() async => throw const ProductFailure(
    'DIAGNOSTICS_UNAVAILABLE',
    '尚未接入诊断收集器。',
    remediation: '不会生成模拟检查结果或空的“正常”诊断包。',
  );
}

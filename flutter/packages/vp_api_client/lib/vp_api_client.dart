import 'package:vp_contracts/vp_contracts.dart';
import 'src/session.dart';
export 'src/session.dart';
export 'src/http_management_api.dart';
export 'src/unavailable_factory.dart'
    if (dart.library.js_interop) 'src/browser_factory.dart';
export 'package:vp_contracts/vp_contracts.dart' show ManagementApi;

const managementUnavailable = ProductFailure(
  'MANAGEMENT_UNAVAILABLE',
  '尚未连接经认证的管理 API。',
  remediation: '此界面不会把浏览器当作 VPN，也不会使用节点凭据取得服务器管理权限。',
  retryable: true,
  definitelyNotApplied: true,
);

/// Default for non-Web compositions without an authenticated HTTP transport.
/// Never replace with sample resources or unauthenticated HTTP.
class UnavailableManagementApi
    implements
        ManagementApi,
        ManagementSession,
        ManagementSessionEpoch,
        PublicationManagementApi {
  const UnavailableManagementApi();
  @override
  bool get canAuthenticate => false;
  @override
  bool get authenticated => false;
  @override
  String get originLabel => '管理地址不可用';
  @override
  Future<void> restoreSession() async => throw managementUnavailable;
  @override
  Future<void> login(
    String username,
    String password, {
    String? secondFactor,
  }) async => throw managementUnavailable;
  @override
  Future<void> logout() async => throw managementUnavailable;
  @override
  void close() {}
  @override
  Future<ManagementSnapshot> snapshot() async => throw managementUnavailable;
  @override
  Future<ChangePlan> planListener(
    ListenerDraft draft,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<ChangePlan> planDeleteListener(
    String id,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<OperationView> applyPlan(
    ChangePlan plan,
    String confirmation,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<OperationView> operation(String id) async =>
      throw managementUnavailable;
  @override
  Future<OperationView?> reconcile(String idempotencyKey) async =>
      throw managementUnavailable;
  @override
  Future<OperationView> cancelOperation(
    String id,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  int get sessionEpoch => 0;
  @override
  void addSessionListener(void Function() listener) {}
  @override
  void removeSessionListener(void Function() listener) {}
  @override
  Future<PublicationWorkspace> readPublicationWorkspace() async =>
      throw managementUnavailable;
  @override
  Future<CredentialInventoryView> credentialInventory() async =>
      throw managementUnavailable;
  @override
  Future<ManagedCredential> generateUuidCredential(
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<ManagedCredential> retireCredential(
    String id,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<List<PublishedSubscription>> publications() async =>
      throw managementUnavailable;
  @override
  Future<PublishedSubscription> getPublication(String id) async =>
      throw managementUnavailable;
  @override
  Future<PublishedSubscription> createPublication(
    PublicationDraft draft,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<PublishedSubscription> replacePublication(
    String id,
    PublicationDraft draft,
    int sourceRevision,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<OneTimePublicationSecret> issuePublicationToken(
    String id,
    int expiresInSeconds,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<PublishedSubscription> revokePublicationToken(
    String id,
    MutationIdentity command,
  ) async => throw managementUnavailable;
  @override
  Future<ChangePlan> prepareNewUuidListener(
    NewUuidListenerInput input,
    ManagedCredential credential,
    MutationIdentity command,
  ) async => throw managementUnavailable;
}

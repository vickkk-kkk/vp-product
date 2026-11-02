// Isolated synthetic ports. Never imported by any production composition.
import 'dart:async';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';

final fixtureCredential = ManagedCredential(
  id: 'credential_fixture',
  revision: 1,
  kind: const CredentialKind('uuid'),
  secretRef: 'secret:fixture_reference',
  state: ManagedCredentialState.available,
  createdAt: DateTime.utc(2026),
  displayKey: 'credential.fixture',
);
PublishedSubscription fixturePublication({
  int revision = 1,
  int sourceRevision = 3,
  PublicationTokenState tokenState = PublicationTokenState.notIssued,
}) => PublishedSubscription(
  id: 'publication_fixture',
  name: '个人设备',
  revision: revision,
  sourceRevision: sourceRevision,
  enabled: true,
  sources: const [
    PublicationSourceMapping(
      listenerId: 'listener_fixture',
      userId: 'user_fixture',
      host: '127.0.0.1',
      port: 19090,
      security: PublicationSecurityNone(),
    ),
  ],
  token: PublicationTokenMetadata(
    state: tokenState,
    version: tokenState == PublicationTokenState.notIssued ? 0 : 1,
    issuedAt: tokenState == PublicationTokenState.notIssued
        ? null
        : DateTime.utc(2026),
    expiresAt: tokenState == PublicationTokenState.notIssued
        ? null
        : DateTime.utc(2027),
  ),
  createdAt: DateTime.utc(2026),
  updatedAt: DateTime.utc(2026),
);
PublicationWorkspace fixtureWorkspace({
  bool supported = true,
  int? observed = 3,
}) => PublicationWorkspace(
  activeRevision: 3,
  observedRevision: observed,
  credentials: [fixtureCredential],
  supportedKinds: supported ? const [CredentialKind('uuid')] : const [],
  sources: const [
    PublicationSourceCandidate(
      listenerId: 'listener_fixture',
      listenerName: '本机开发节点',
      userId: 'user_fixture',
      protocol: 'vless',
      transport: 'tcp',
      securityKind: 'none',
      bindAddress: '127.0.0.1',
      bindPort: 19090,
      selectable: true,
      reason: '实际观测可用',
    ),
  ],
  publications: [fixturePublication()],
  developmentBuild: true,
  presets: const [],
);
const syntheticIssuedUrl =
    'http://localhost:18081/subscriptions/v1/publication_fixture/vps1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
OneTimePublicationSecret fixtureSecret(int epoch) => OneTimePublicationSecret(
  publication: fixturePublication(
    revision: 2,
    tokenState: PublicationTokenState.active,
  ),
  subscriptionUrl: syntheticIssuedUrl,
  sessionEpoch: epoch,
  developmentLoopback: true,
);

class PublicationFixtureApi extends UnavailableManagementApi
    implements ManagementSessionEpoch {
  int epoch = 0;
  bool signedIn = true;
  final listeners = <void Function()>{};
  PublicationWorkspace workspace = fixtureWorkspace();
  Completer<PublicationWorkspace>? pendingRead;
  Completer<ManagedCredential>? pendingCredential;
  Completer<OneTimePublicationSecret>? pendingIssue;
  Object? generationFailure, issuanceFailure, metadataFailure;
  final generationCommands = <MutationIdentity>[],
      issueCommands = <MutationIdentity>[];
  int creates = 0,
      replaces = 0,
      revokes = 0,
      metadataReads = 0,
      prepares = 0,
      applies = 0;
  NewUuidListenerInput? preparedInput;
  @override
  bool get canAuthenticate => true;
  @override
  bool get authenticated => signedIn;
  @override
  String get originLabel => 'http://localhost:18081';
  @override
  int get sessionEpoch => epoch;
  @override
  void addSessionListener(void Function() listener) => listeners.add(listener);
  @override
  void removeSessionListener(void Function() listener) =>
      listeners.remove(listener);
  void changeSession() {
    epoch++;
    for (final listener in listeners.toList()) {
      listener();
    }
  }

  @override
  Future<void> logout() async {
    signedIn = false;
    changeSession();
  }

  @override
  Future<PublicationWorkspace> readPublicationWorkspace() async =>
      pendingRead == null ? workspace : pendingRead!.future;
  @override
  Future<ManagedCredential> generateUuidCredential(
    MutationIdentity command,
  ) async {
    generationCommands.add(command);
    if (generationFailure != null) throw generationFailure!;
    return pendingCredential == null
        ? fixtureCredential
        : pendingCredential!.future;
  }

  @override
  Future<OneTimePublicationSecret> issuePublicationToken(
    String id,
    int seconds,
    MutationIdentity command,
  ) async {
    issueCommands.add(command);
    if (issuanceFailure != null) throw issuanceFailure!;
    return pendingIssue == null ? fixtureSecret(epoch) : pendingIssue!.future;
  }

  @override
  Future<PublishedSubscription> getPublication(String id) async {
    metadataReads++;
    if (metadataFailure != null) throw metadataFailure!;
    return fixturePublication(
      revision: 2,
      tokenState: PublicationTokenState.active,
    );
  }

  @override
  Future<PublishedSubscription> createPublication(
    PublicationDraft draft,
    MutationIdentity command,
  ) async {
    creates++;
    return fixturePublication();
  }

  @override
  Future<PublishedSubscription> replacePublication(
    String id,
    PublicationDraft draft,
    int sourceRevision,
    MutationIdentity command,
  ) async {
    replaces++;
    return fixturePublication(revision: 2, sourceRevision: sourceRevision);
  }

  @override
  Future<PublishedSubscription> revokePublicationToken(
    String id,
    MutationIdentity command,
  ) async {
    revokes++;
    return fixturePublication(
      revision: 2,
      tokenState: PublicationTokenState.revoked,
    );
  }

  @override
  Future<ManagementSnapshot> snapshot() async => ManagementSnapshot(
    hostLabel: 'Widget fixture only',
    safeManagementOrigin: originLabel,
    revision: '3',
    observedRevision: '3',
    observedAt: DateTime.utc(2026),
    listeners: const [],
    presets: const [],
    operations: const [],
    developmentBuild: true,
  );
  @override
  Future<ChangePlan> prepareNewUuidListener(
    NewUuidListenerInput input,
    ManagedCredential credential,
    MutationIdentity command,
  ) async {
    prepares++;
    preparedInput = input;
    return ChangePlan(
      id: 'plan_fixture',
      hash: 'a' * 64,
      baseRevision: '3',
      target: 'Widget fixture only',
      changes: [PlanChange(field: '节点名称', before: '无', after: input.name)],
      impacts: const ['仅组件测试'],
      recovery: '仅组件测试',
      expiresAt: DateTime.now().add(const Duration(minutes: 5)),
      confirmationPhrase: '确认测试计划',
    );
  }

  @override
  Future<OperationView> applyPlan(
    ChangePlan plan,
    String confirmation,
    MutationIdentity command,
  ) async {
    applies++;
    return const OperationView(
      id: 'operation_fixture',
      stage: '验证运行结果',
      status: '进行中',
      lastMessage: '测试操作已接受，不是实际连接证明。',
      cancellable: false,
      terminal: false,
    );
  }

  @override
  Future<OperationView> operation(String id) async => const OperationView(
    id: 'operation_fixture',
    stage: '提交修订',
    status: '操作成功',
    lastMessage: '组件测试终态，不是运行验证。',
    cancellable: false,
    terminal: true,
  );
}

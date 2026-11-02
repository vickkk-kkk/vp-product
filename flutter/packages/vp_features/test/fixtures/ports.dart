// Test-only ports. Never import from lib/ or application composition roots.
import 'dart:async';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_runtime_platform/vp_runtime_platform.dart';

Revisioned<ClientInventory> inventory({String revision = '1'}) => Revisioned(
  revision: revision,
  observedAt: DateTime.now(),
  value: const ClientInventory(nodes: [], subscriptions: []),
);

class TestRepository extends UnavailableClientRepository {
  Revisioned<ClientInventory> current = inventory();
  Object? readError;
  Completer<MutationReceipt>? pending;
  int mutations = 0;
  MutationIdentity? lastCommand;
  MutationReceipt? reconciled;
  @override
  Future<Revisioned<ClientInventory>> read() async {
    if (readError != null) throw readError!;
    return current;
  }

  @override
  Future<MutationReceipt> renameNode(
    String id,
    String name,
    MutationIdentity command,
  ) {
    mutations++;
    lastCommand = command;
    return pending?.future ??
        Future.value(
          const MutationReceipt(operationId: 'operation:test', revision: '2'),
        );
  }

  @override
  Future<MutationReceipt?> reconcile(String idempotencyKey) async => reconciled;
}

ConnectionView connection({
  int sequence = 1,
  int generation = 1,
  String instance = 'instance:test',
  ConnectionPhase phase = ConnectionPhase.disconnected,
}) => ConnectionView(
  instanceId: instance,
  generation: generation,
  sequence: sequence,
  phase: phase,
  observedAt: DateTime.now(),
  validUntil: DateTime.now().add(const Duration(minutes: 1)),
  evidence: const [],
  summary: 'Test observation',
  canConnect: true,
  canDisconnect: true,
  canCancel: false,
  revision: '1',
);

class TestRuntime extends UnavailableRuntime {
  ConnectionView current = connection();
  final stream = StreamController<RuntimeEvent>.broadcast();
  int connects = 0;
  Object? connectError;
  MutationIdentity? lastCommand;
  @override
  Future<ConnectionView> snapshot() async => current;
  @override
  Stream<RuntimeEvent> events({required int afterSequence}) => stream.stream;
  @override
  Future<String> connect({
    required String nodeId,
    required MutationIdentity command,
  }) async {
    connects++;
    lastCommand = command;
    if (connectError != null) throw connectError!;
    return 'operation:connect';
  }

  @override
  Future<void> dispose() async => stream.close();
}

ImportPreview preview() => ImportPreview(
  id: 'preview:test',
  baseRevision: '1',
  items: const [
    ImportItem(
      id: 'entry:1',
      safeName: 'Test node',
      status: ImportItemStatus.ready,
      explanation: 'Test fixture',
    ),
    ImportItem(
      id: 'entry:2',
      safeName: 'Bad entry',
      status: ImportItemStatus.malformed,
      explanation: 'Invalid fixture',
    ),
  ],
  warnings: const [],
  expiresAt: DateTime.now().add(const Duration(minutes: 1)),
  isNodeExtraction: false,
  requiresExplicitNodeExtraction: false,
);

class TestImporter extends UnavailableImportService {
  final parsed = Completer<ImportPreview>();
  int commits = 0;
  Object? commitError;
  @override
  Future<ImportPreview> previewText(String text, String expectedRevision) =>
      parsed.future;
  @override
  Future<ImportCommit> commit(
    ImportPreview preview,
    ImportSelection selection,
    MutationIdentity command,
  ) async {
    commits++;
    if (commitError != null) throw commitError!;
    return const ImportCommit(
      operationId: 'operation:import',
      imported: 1,
      rejected: {},
      revision: '2',
    );
  }

  @override
  Future<ImportCommit?> reconcile(String idempotencyKey) async => null;
}

class TestManagement extends UnavailableManagementApi {
  int applications = 0;
  Completer<OperationView>? pendingApply;
  Object? applyError;
  Object? cancelError;
  Object? operationError;
  int cancellations = 0;
  MutationIdentity? cancelIdentity;
  @override
  Future<ManagementSnapshot> snapshot() async => ManagementSnapshot(
    hostLabel: 'Test host',
    safeManagementOrigin: 'https://example.invalid',
    revision: '1',
    observedRevision: '1',
    observedAt: DateTime.now(),
    listeners: const [],
    presets: const [],
    operations: const [],
  );
  @override
  Future<OperationView> applyPlan(
    ChangePlan plan,
    String confirmation,
    MutationIdentity command,
  ) async {
    applications++;
    if (applyError != null) throw applyError!;
    if (pendingApply != null) return pendingApply!.future;
    return OperationView(
      id: 'operation:test',
      stage: 'commit',
      status: 'succeeded',
      lastMessage: 'Test-only operation',
      cancellable: false,
      terminal: true,
    );
  }

  @override
  Future<OperationView> cancelOperation(
    String id,
    MutationIdentity command,
  ) async {
    cancellations++;
    cancelIdentity = command;
    if (cancelError != null) throw cancelError!;
    return OperationView(
      id: id,
      stage: 'stop',
      status: 'running',
      lastMessage: 'Test',
      cancellable: false,
      terminal: false,
    );
  }

  @override
  Future<OperationView> operation(String id) async {
    if (operationError != null) throw operationError!;
    return OperationView(
      id: id,
      stage: 'verify',
      status: 'running',
      lastMessage: 'Test',
      cancellable: true,
      terminal: false,
    );
  }

  @override
  Future<OperationView?> reconcile(String idempotencyKey) async => null;
}

class LifecycleImporter extends TestImporter implements ImportPreviewLifecycle {
  final discarded = <String>[];
  @override
  void discardPreview(String previewId) {
    discarded.add(previewId);
  }
}

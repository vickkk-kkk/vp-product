/// UI read models and application ports, NOT generated JSON/wire DTOs.
/// Canonical wire ownership: crates/vp-domain and contracts/schema.
/// Adapters must validate schema and project canonical types into these models.
library;

export 'src/runtime_dto.dart';
export 'src/publication.dart';

class ProductFailure implements Exception {
  const ProductFailure(
    this.code,
    this.message, {
    this.remediation,
    this.fieldErrors = const {},
    this.diagnosticId,
    this.retryable = false,
    this.outcomeUnknown = false,
    this.definitelyNotApplied = false,
  });
  final String code, message;
  final String? remediation, diagnosticId;
  final Map<String, String> fieldErrors;
  final bool retryable;

  /// A mutation may have been accepted: reconcile its idempotency key, don't resubmit.
  final bool outcomeUnknown;

  /// Set only when the adapter proves no mutation was accepted (e.g. no adapter).
  final bool definitelyNotApplied;
  @override
  String toString() => code; // Never emit raw payloads or secret-bearing exception text.
}

ProductFailure safeFailure(Object error) => error is ProductFailure
    ? error
    : const ProductFailure(
        'UNEXPECTED_ERROR',
        '操作未完成。原有内容已保留。',
        remediation: '查看脱敏诊断信息；不要重复提交结果未知的操作。',
      );

/// An unclassified submission error is never evidence of non-application.
ProductFailure safeMutationFailure(Object error) {
  final failure = safeFailure(error);
  if (failure.definitelyNotApplied) return failure;
  return ProductFailure(
    failure.code,
    failure.message,
    remediation: failure.remediation,
    fieldErrors: failure.fieldErrors,
    diagnosticId: failure.diagnosticId,
    retryable: false,
    outcomeUnknown: true,
  );
}

class Revisioned<T> {
  const Revisioned({
    required this.revision,
    required this.value,
    required this.observedAt,
  });
  final String revision;
  final T value;
  final DateTime observedAt;
}

enum CapabilityStatus { certified, experimental, pending, unsupported }

class CapabilityView {
  const CapabilityView({
    required this.key,
    required this.label,
    required this.status,
    required this.reason,
    this.evidenceIds = const [],
  });
  final String key, label, reason;
  final CapabilityStatus status;
  final List<String> evidenceIds;
  bool get runnable =>
      status == CapabilityStatus.certified && evidenceIds.isNotEmpty;
}

class NodeView {
  const NodeView({
    required this.id,
    required this.name,
    required this.endpoint,
    required this.protocolLabel,
    required this.transportLabel,
    required this.sourceLabel,
    required this.capability,
    this.sourceId,
    this.tags = const [],
  });
  final String id, name, endpoint, protocolLabel, transportLabel, sourceLabel;
  final String? sourceId;
  final List<String> tags;
  final CapabilityView capability;
  bool matches(String query) => [
    name,
    endpoint,
    protocolLabel,
    transportLabel,
    sourceLabel,
    ...tags,
  ].join(' ').toLowerCase().contains(query.trim().toLowerCase());
}

class SubscriptionView {
  const SubscriptionView({
    required this.id,
    required this.name,
    required this.safeOrigin,
    required this.nodeCount,
    this.lastAttempt,
    this.lastSuccess,
    this.error,
  });
  final String id, name;

  /// Origin only, no path, query, URL credentials, or token. Adapters enforce it.
  final String safeOrigin;
  final int nodeCount;
  final DateTime? lastAttempt, lastSuccess;
  final ProductFailure? error;
}

/// Explicit, non-secret user DNS choice. Adapters validate numeric endpoints;
/// no platform DNS or provider default is implied by an absent configuration.
class UserDnsSettings {
  UserDnsSettings({required List<String> servers})
    : servers = List.unmodifiable(servers);
  final List<String> servers;
  String get route => 'selected_proxy';
}

/// Optional platform control; notification consent is not VPN consent or health.
class RuntimeNotificationPermission {
  const RuntimeNotificationPermission({
    required this.granted,
    required this.canRequest,
  });
  final bool granted, canRequest;
}

abstract interface class RuntimeNotificationControl {
  Future<RuntimeNotificationPermission> notificationPermission();
  Future<RuntimeNotificationPermission> requestNotificationPermission();
}

class ClientInventory {
  const ClientInventory({
    required this.nodes,
    required this.subscriptions,
    this.selectedNodeId,
    this.userDns,
  });
  final UserDnsSettings? userDns;
  final List<NodeView> nodes;
  final List<SubscriptionView> subscriptions;
  final String? selectedNodeId;
  NodeView? get selectedNode {
    for (final node in nodes) {
      if (node.id == selectedNodeId) return node;
    }
    return null;
  }
}

class MutationIdentity {
  const MutationIdentity({
    required this.requestId,
    required this.idempotencyKey,
    required this.expectedRevision,
  });
  final String requestId, idempotencyKey, expectedRevision;
}

class MutationReceipt {
  const MutationReceipt({required this.operationId, required this.revision});
  final String operationId, revision;
}

/// No credential values in read models, route paths, widget keys, or logs.
abstract interface class ClientRepository {
  Future<Revisioned<ClientInventory>> read();
  Future<MutationReceipt> renameNode(
    String id,
    String name,
    MutationIdentity command,
  );
  Future<MutationReceipt> selectNode(String id, MutationIdentity command);

  /// The repository MUST reject deletion of a node used by an active runtime.
  Future<MutationReceipt> deleteNodes(
    Set<String> ids,
    MutationIdentity command,
  );
  Future<MutationReceipt> saveSubscription({
    String? id,
    required String name,
    String? replacementUrl,
    required MutationIdentity command,
  });
  Future<MutationReceipt> deleteSubscription(
    String id,
    MutationIdentity command,
  );

  /// Refresh stages a diff. It does not silently replace the active inventory.
  Future<ImportPreview> previewSubscriptionRefresh(String id);
  Future<MutationReceipt?> reconcile(String idempotencyKey);
}

/// Optional settings capability. Null explicitly clears the user's choice.
/// Saving uses the inventory revision, native mutation gate and durable receipts;
/// it never starts a connection. Reconcile through ClientRepository.reconcile.
abstract interface class ClientDnsSettingsRepository {
  Future<MutationReceipt> saveUserDns(
    UserDnsSettings? settings,
    MutationIdentity command,
  );
}

enum ImportItemStatus { ready, duplicate, unsupported, malformed }

/// Review action set by the authoritative staging adapter, never by source text.
enum ImportAction { add, update, remove }

enum DuplicateResolution { keepExisting, updateSameSource, saveCopy }

class ImportItem {
  const ImportItem({
    required this.id,
    required this.safeName,
    required this.status,
    required this.explanation,
    this.fields = const {},
    this.allowedResolutions = const {},
    this.action = ImportAction.add,
  });
  final String id, safeName, explanation;
  final ImportItemStatus status;
  final ImportAction action;
  final Map<String, String> fields;
  final Set<DuplicateResolution> allowedResolutions;
  bool get selectable =>
      status == ImportItemStatus.ready || status == ImportItemStatus.duplicate;
}

class ImportPreview {
  const ImportPreview({
    required this.id,
    required this.baseRevision,
    required this.items,
    required this.warnings,
    required this.expiresAt,
    required this.isNodeExtraction,
    required this.requiresExplicitNodeExtraction,
  });
  final String id, baseRevision;
  final List<ImportItem> items;
  final List<String> warnings;
  final DateTime expiresAt;
  final bool isNodeExtraction, requiresExplicitNodeExtraction;
}

class ImportSelection {
  const ImportSelection({
    required this.selectedIds,
    required this.duplicates,
    required this.acceptNodeExtraction,
  });
  final Set<String> selectedIds;
  final Map<String, DuplicateResolution> duplicates;
  final bool acceptNodeExtraction;
}

class ImportCommit {
  const ImportCommit({
    required this.operationId,
    required this.imported,
    required this.rejected,
    required this.revision,
    this.removed = 0,
  });
  final String operationId, revision;
  final int imported, removed;
  final Map<String, ProductFailure> rejected;
}

/// Optional lifecycle for native staged credentials. Implementations release
/// only the specified preview, so a late cancelled parse cannot erase a newer one.
/// Optional cancellation for an explicitly requested source refresh. No source
/// URL or credentials cross this lifecycle boundary.
abstract interface class SubscriptionRefreshLifecycle {
  void cancelSubscriptionRefresh(String sourceId);
}

abstract interface class ImportPreviewLifecycle {
  void discardPreview(String previewId);
}

abstract interface class ImportService {
  /// Pure native codec; must not fetch a URL or start runtime as a side effect.
  Future<ImportPreview> previewText(String text, String expectedRevision);
  Future<ImportCommit> commit(
    ImportPreview preview,
    ImportSelection selection,
    MutationIdentity command,
  );
  Future<ImportCommit?> reconcile(String idempotencyKey);
}

enum EvidenceState { unknown, checking, passed, failed, notApplicable }

class EvidenceView {
  const EvidenceView({
    required this.label,
    required this.state,
    required this.detail,
    this.observedAt,
    this.requiredForConnection = true,
  });
  final String label, detail;
  final EvidenceState state;
  final DateTime? observedAt;
  final bool requiredForConnection;
}

enum ConnectionPhase {
  unavailable,
  unconfigured,
  disconnected,
  awaitingPermission,
  preparing,
  starting,
  verifying,
  enabledUnverified,
  verified,
  degraded,
  reconnecting,
  stopping,
  recovering,
  failed,
  recoveryRequired,
}

class ConnectionView {
  const ConnectionView({
    required this.instanceId,
    required this.generation,
    required this.sequence,
    required this.phase,
    required this.observedAt,
    required this.validUntil,
    required this.evidence,
    required this.summary,
    required this.canConnect,
    required this.canDisconnect,
    required this.canCancel,
    this.nodeId,
    this.revision,
    this.operationId,
  });
  final String instanceId;
  final int generation, sequence;
  final ConnectionPhase phase;
  final DateTime observedAt, validUntil;
  final List<EvidenceView> evidence;
  final String summary;
  final String? nodeId, revision, operationId;
  final bool canConnect, canDisconnect, canCancel;
  bool isStale(DateTime now) =>
      now.isBefore(observedAt) || !now.isBefore(validUntil);
  bool get isVerified =>
      phase == ConnectionPhase.verified &&
      evidence.any((item) => item.state == EvidenceState.passed) &&
      evidence
          .where((item) => item.requiredForConnection)
          .every((item) => item.state == EvidenceState.passed);
}

sealed class RuntimeEvent {
  const RuntimeEvent();
}

class RuntimeObservation extends RuntimeEvent {
  const RuntimeObservation(this.snapshot);
  final ConnectionView snapshot;
}

class RuntimeResyncRequired extends RuntimeEvent {
  const RuntimeResyncRequired();
}

class RuntimeLost extends RuntimeEvent {
  const RuntimeLost(this.error);
  final ProductFailure error;
}

abstract interface class RuntimeControl {
  Future<ConnectionView> snapshot();

  /// Events after sequence; native adapter must bridge bounded stream and resync gaps.
  Stream<RuntimeEvent> events({required int afterSequence});
  Future<String> connect({
    required String nodeId,
    required MutationIdentity command,
  });
  Future<String> disconnect({
    required String expectedInstanceId,
    required int expectedGeneration,
    required MutationIdentity command,
  });
  Future<String> cancel({
    required String expectedInstanceId,
    required String operationId,
    required MutationIdentity command,
  });

  /// null means still unknown, not safe to resubmit.
  Future<String?> reconcile(String idempotencyKey);
  Future<void> dispose();
}

class ListenerView {
  const ListenerView({
    required this.id,
    required this.name,
    required this.presetKey,
    required this.bind,
    required this.port,
    required this.desiredEnabled,
    required this.observedState,
    required this.desiredRevision,
    required this.observedRevision,
    this.problem,
  });
  final String id, name, presetKey, bind, observedState, desiredRevision;
  final String? observedRevision;
  final int port;
  final bool desiredEnabled;
  final ProductFailure? problem;
}

class PresetView {
  const PresetView({
    required this.key,
    required this.name,
    required this.description,
    required this.capability,
  });
  final String key, name, description;
  final CapabilityView capability;
}

class OperationView {
  const OperationView({
    required this.id,
    required this.stage,
    required this.status,
    this.startedAt,
    required this.lastMessage,
    required this.cancellable,
    required this.terminal,
    this.error,
  });
  final String id, stage, status, lastMessage;
  final DateTime? startedAt;
  final bool cancellable, terminal;
  final ProductFailure? error;
}

class ManagementSnapshot {
  const ManagementSnapshot({
    required this.hostLabel,
    required this.safeManagementOrigin,
    required this.revision,
    required this.observedRevision,
    required this.observedAt,
    required this.listeners,
    required this.presets,
    required this.operations,
    this.developmentBuild,
  });
  final String hostLabel, safeManagementOrigin, revision;
  final String? observedRevision;
  final bool? developmentBuild;
  final DateTime observedAt;
  final List<ListenerView> listeners;
  final List<PresetView> presets;
  final List<OperationView> operations;
}

class ListenerDraft {
  const ListenerDraft({
    required this.name,
    required this.presetKey,
    required this.bind,
    required this.port,
    this.listenerId,
    required this.enabled,
  });
  final String? listenerId;
  final String name, presetKey, bind;
  final int port;
  final bool enabled;
}

class PlanChange {
  const PlanChange({
    required this.field,
    required this.before,
    required this.after,
  });
  final String field, before, after;
}

class ChangePlan {
  const ChangePlan({
    required this.id,
    required this.hash,
    required this.baseRevision,
    required this.target,
    required this.changes,
    required this.impacts,
    required this.recovery,
    required this.expiresAt,
    required this.confirmationPhrase,
  });
  final String id, hash, baseRevision, target, recovery, confirmationPhrase;
  final List<PlanChange> changes;
  final List<String> impacts;
  final DateTime expiresAt;
}

abstract interface class ManagementApi {
  Future<ManagementSnapshot> snapshot();
  Future<ChangePlan> planListener(
    ListenerDraft draft,
    MutationIdentity command,
  );
  Future<ChangePlan> planDeleteListener(String id, MutationIdentity command);
  Future<OperationView> applyPlan(
    ChangePlan plan,
    String confirmation,
    MutationIdentity command,
  );
  Future<OperationView> operation(String id);
  Future<OperationView?> reconcile(String idempotencyKey);
  Future<OperationView> cancelOperation(String id, MutationIdentity command);
}

class DiagnosticReport {
  const DiagnosticReport({
    required this.generatedAt,
    required this.checks,
    required this.redactedLines,
    required this.productVersion,
    required this.coreIdentity,
  });
  final DateTime generatedAt;
  final List<EvidenceView> checks;
  final List<String> redactedLines;
  final String productVersion, coreIdentity;
}

abstract interface class DiagnosticsService {
  Future<DiagnosticReport> inspect();
}

import 'dart:async';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'state.dart';

// Development builds may exercise pending presets without changing certification.
const developmentConnectionsEnabled =
    kDebugMode &&
    bool.fromEnvironment('VP_ENABLE_DEV_CONNECTIONS', defaultValue: false);

bool developmentConnectionEligible(CapabilityView capability) =>
    developmentConnectionsEnabled &&
    (capability.status == CapabilityStatus.pending ||
        capability.status == CapabilityStatus.experimental);

String newRequestId() {
  final random = Random.secure();
  return List.generate(
    16,
    (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
  ).join();
}

MutationIdentity identityFor(String revision) => MutationIdentity(
  requestId: newRequestId(),
  idempotencyKey: newRequestId(),
  expectedRevision: revision,
);

abstract class SafeController extends ChangeNotifier {
  bool _disposed = false;
  bool get disposed => _disposed;
  void changed() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}

class InventoryController extends SafeController {
  InventoryController(this.repository);
  final ClientRepository repository;
  LoadState<Revisioned<ClientInventory>> state = const Loading();
  MutationState mutation = const MutationIdle();
  int _readEpoch = 0;
  Future<void> refresh() async {
    final epoch = ++_readEpoch;
    final old = state.previous;
    state = Loading(old);
    changed();
    try {
      final result = await repository.read();
      if (disposed || epoch != _readEpoch) return;
      state = Loaded(result);
    } catch (error) {
      if (disposed || epoch != _readEpoch) return;
      state = LoadFailed(safeFailure(error), old);
    }
    changed();
  }

  Future<void> mutate(
    String label,
    Future<MutationReceipt> Function(MutationIdentity) action,
  ) async {
    final current = state;
    if (mutation.blocked || current is! Loaded<Revisioned<ClientInventory>>)
      return;
    final identity = identityFor(current.value.revision);
    mutation = MutationRunning(label, identity);
    changed();
    try {
      final receipt = await action(identity);
      if (disposed) return;
      mutation = MutationSucceeded(label, receipt.operationId);
      changed();
      await refresh();
    } catch (error) {
      if (disposed) return;
      final failure = safeMutationFailure(error);
      mutation = failure.outcomeUnknown
          ? MutationUncertain(failure, identity)
          : MutationFailed(failure);
      changed();
    }
  }

  Future<void> reconcile() async {
    final pending = mutation;
    if (pending is! MutationUncertain) return;
    try {
      final receipt = await repository.reconcile(
        pending.identity.idempotencyKey,
      );
      if (disposed) return;
      if (receipt != null) {
        mutation = MutationSucceeded('已找回原操作', receipt.operationId);
        await refresh();
      }
      // null is not proof of failure and never permits a new submission.
    } catch (error) {
      if (!disposed)
        mutation = MutationUncertain(safeFailure(error), pending.identity);
    }
    changed();
  }
}

class ConnectionController extends SafeController {
  ConnectionController(this.runtime);
  final RuntimeControl runtime;
  LoadState<ConnectionView> state = const Loading();
  MutationState mutation = const MutationIdle();

  /// Exact target retained with the command identity while its outcome is unknown.
  String? mutationNodeId;
  StreamSubscription<RuntimeEvent>? _events;
  Timer? _expiry;
  int _readEpoch = 0;
  Future<void>? _readInFlight;
  Timer? _observationTimer;
  bool _observationActive = false;
  int _observationFailures = 0;
  bool get isRefreshing => _readInFlight != null;

  /// The visible/resumed page owns this lease; inactive pages never poll.
  void setObservationActive(bool active) {
    if (disposed || active == _observationActive) return;
    _observationActive = active;
    _observationTimer?.cancel();
    if (active) unawaited(refresh());
  }

  void _scheduleObservation() {
    _observationTimer?.cancel();
    if (!_observationActive || disposed) return;
    final seconds = switch (_observationFailures) {
      0 => 10,
      1 => 20,
      2 => 40,
      _ => 60,
    };
    _observationTimer = Timer(Duration(seconds: seconds), () {
      if (_observationActive && !disposed) unawaited(refresh());
    });
  }

  Future<void> refresh() {
    if (disposed) return Future.value();
    final pending = _readInFlight;
    if (pending != null) return pending;
    _observationTimer?.cancel();
    final read = _refreshOnce().whenComplete(() {
      _readInFlight = null;
      _observationFailures = state is LoadFailed<ConnectionView>
          ? _observationFailures + 1
          : 0;
      _scheduleObservation();
      changed();
    });
    _readInFlight = read;
    return read;
  }

  Future<void> _refreshOnce() async {
    final epoch = ++_readEpoch;
    final old = state.previous;
    state = Loading(old);
    changed();
    try {
      final snapshot = await runtime.snapshot();
      if (disposed || epoch != _readEpoch) return;
      _accept(snapshot, allowSame: true);
      await _events?.cancel();
      if (disposed || epoch != _readEpoch) return;
      _events = runtime
          .events(afterSequence: snapshot.sequence)
          .listen(
            (event) {
              if (disposed || epoch != _readEpoch) return;
              switch (event) {
                case RuntimeObservation(:final snapshot):
                  final previous = state.previous;
                  if (previous != null &&
                      (snapshot.instanceId != previous.instanceId ||
                          snapshot.generation > previous.generation ||
                          snapshot.sequence > previous.sequence + 1)) {
                    unawaited(refresh());
                  } else {
                    _accept(snapshot);
                  }
                case RuntimeResyncRequired():
                  unawaited(refresh());
                case RuntimeLost(:final error):
                  state = LoadFailed(error, state.previous);
                  changed();
              }
            },
            onError: (Object error) {
              if (!disposed && epoch == _readEpoch) {
                state = LoadFailed(safeFailure(error), state.previous);
                changed();
              }
            },
            onDone: () {
              if (!disposed && epoch == _readEpoch) {
                state = LoadFailed(
                  const ProductFailure(
                    'EVENT_STREAM_CLOSED',
                    '状态同步已中断。',
                    retryable: true,
                  ),
                  state.previous,
                );
                changed();
              }
            },
          );
    } catch (error) {
      if (disposed || epoch != _readEpoch) return;
      state = LoadFailed(safeFailure(error), old);
      changed();
    }
  }

  void _accept(ConnectionView next, {bool allowSame = false}) {
    if (disposed) return;
    final old = state.previous;
    if (old != null &&
        old.instanceId == next.instanceId &&
        (next.generation < old.generation ||
            (next.generation == old.generation &&
                (allowSame
                    ? next.sequence < old.sequence
                    : next.sequence <= old.sequence))))
      return;
    state = Loaded(next);
    _expiry?.cancel();
    final remaining = next.validUntil.difference(DateTime.now());
    if (remaining > Duration.zero) _expiry = Timer(remaining, changed);
    changed();
  }

  Future<void> connectNode({
    required NodeView node,
    required String inventoryRevision,
    bool development = false,
  }) async {
    final snapshot = state.previous;
    if (snapshot?.canConnect != true ||
        !(node.capability.runnable ||
            development && developmentConnectionEligible(node.capability))) {
      return;
    }
    await command(
      development ? '正在请求未认证测试连接' : '正在请求连接',
      (id) => runtime.connect(nodeId: node.id, command: id),
      expectedRevision: inventoryRevision,
      targetNodeId: node.id,
    );
  }

  Future<void> command(
    String label,
    Future<String> Function(MutationIdentity) action, {
    String? expectedRevision,
    String? targetNodeId,
  }) async {
    if (mutation.blocked || state is! Loaded<ConnectionView>) return;
    final snapshot = state.previous!;
    if (snapshot.isStale(DateTime.now())) return;
    final identity = identityFor(
      expectedRevision ?? snapshot.revision ?? 'unknown',
    );
    mutationNodeId = targetNodeId;
    mutation = MutationRunning(label, identity);
    changed();
    try {
      final operation = await action(identity);
      if (disposed) return;
      // Command acknowledgement is not an observed connection state.
      mutation = MutationSucceeded('请求已接受，等待运行组件确认', operation);
      await refresh();
    } catch (error) {
      if (disposed) return;
      final failure = safeMutationFailure(error);
      mutation = failure.outcomeUnknown
          ? MutationUncertain(failure, identity)
          : MutationFailed(failure);
    }
    changed();
  }

  Future<void> reconcile() async {
    final pending = mutation;
    if (pending is! MutationUncertain) return;
    try {
      final operationId = await runtime.reconcile(
        pending.identity.idempotencyKey,
      );
      if (disposed) return;
      if (operationId != null) {
        mutation = MutationSucceeded('已找回原连接操作，等待实际状态', operationId);
        await refresh();
      }
    } catch (error) {
      if (!disposed)
        mutation = MutationUncertain(safeFailure(error), pending.identity);
    }
    changed();
  }

  @override
  void dispose() {
    _observationActive = false;
    _observationTimer?.cancel();
    _expiry?.cancel();
    unawaited(_events?.cancel());
    super.dispose();
  }
}

sealed class ImportState {
  const ImportState();
}

class ImportEditing extends ImportState {
  const ImportEditing([this.error]);
  final ProductFailure? error;
}

class ImportParsing extends ImportState {
  const ImportParsing();
}

class ImportReview extends ImportState {
  const ImportReview(this.preview, {this.error});
  final ImportPreview preview;
  final ProductFailure? error;
}

class ImportSaving extends ImportState {
  const ImportSaving(this.preview, this.identity);
  final ImportPreview preview;
  final MutationIdentity identity;
}

class ImportUncertain extends ImportState {
  const ImportUncertain(this.preview, this.identity, this.error);
  final ImportPreview preview;
  final MutationIdentity identity;
  final ProductFailure error;
}

class ImportComplete extends ImportState {
  const ImportComplete(this.result);
  final ImportCommit result;
}

class ImportController extends SafeController {
  ImportController(this.service);
  final ImportService service;
  ImportState state = const ImportEditing();
  int _epoch = 0;
  Future<void> parse(String text, String revision) async {
    if (state is ImportParsing ||
        state is ImportSaving ||
        state is ImportUncertain)
      return;
    if (text.trim().isEmpty) {
      state = const ImportEditing(
        ProductFailure('INPUT_REQUIRED', '请粘贴需要解析的节点文本。'),
      );
      changed();
      return;
    }
    // Defensive UI limit, authoritative codec enforces byte/depth/node limits.
    if (text.length > 1024 * 1024) {
      state = const ImportEditing(
        ProductFailure('INPUT_TOO_LARGE', '文本过大，请缩小导入范围。'),
      );
      changed();
      return;
    }
    final epoch = ++_epoch;
    state = const ImportParsing();
    changed();
    try {
      final preview = await service.previewText(text, revision);
      if (!disposed && epoch == _epoch) {
        state = ImportReview(preview);
      } else {
        _discard(preview.id);
      }
    } catch (error) {
      if (!disposed && epoch == _epoch)
        state = ImportEditing(safeFailure(error));
    }
    changed();
  }

  void cancelParsing() {
    if (state is ImportParsing) {
      _epoch++;
      state = const ImportEditing();
      changed();
    }
  }

  void _discard(String id) {
    final lifecycle = service;
    if (lifecycle is ImportPreviewLifecycle) {
      try {
        (lifecycle as ImportPreviewLifecycle).discardPreview(id);
      } catch (_) {
        /* Never expose native payloads. */
      }
    }
  }

  void edit() {
    final current = state;
    if (current is ImportReview) {
      _discard(current.preview.id);
      state = const ImportEditing();
      changed();
    }
  }

  Future<void> commit(ImportSelection selection) async {
    final current = state;
    if (current is! ImportReview) return;
    final preview = current.preview;
    ProductFailure? invalid;
    if (!DateTime.now().isBefore(preview.expiresAt))
      invalid = const ProductFailure('PREVIEW_EXPIRED', '预览已过期，请重新解析。');
    if (selection.selectedIds.isEmpty)
      invalid = const ProductFailure('SELECTION_REQUIRED', '请至少选择一项。');
    if (preview.requiresExplicitNodeExtraction &&
        !selection.acceptNodeExtraction)
      invalid = const ProductFailure(
        'EXTRACTION_CONSENT_REQUIRED',
        '请确认仅导入节点，不导入未支持的规则与配置。',
      );
    for (final id in selection.selectedIds) {
      final matches = preview.items.where((item) => item.id == id);
      if (matches.length != 1 || !matches.first.selectable) {
        invalid = const ProductFailure(
          'IMPORT_SELECTION_INVALID',
          '选择包含无法导入的项。',
        );
        break;
      }
      final item = matches.first;
      if (item.status == ImportItemStatus.duplicate &&
          !item.allowedResolutions.contains(selection.duplicates[id])) {
        invalid = const ProductFailure(
          'DUPLICATE_RESOLUTION_REQUIRED',
          '请选择每个重复项的处理方式。',
        );
        break;
      }
    }
    if (invalid != null) {
      state = ImportReview(preview, error: invalid);
      changed();
      return;
    }
    final identity = identityFor(preview.baseRevision);
    state = ImportSaving(preview, identity);
    changed();
    try {
      final result = await service.commit(preview, selection, identity);
      if (!disposed) state = ImportComplete(result);
    } catch (error) {
      if (disposed) return;
      final failure = safeMutationFailure(error);
      state = failure.outcomeUnknown
          ? ImportUncertain(preview, identity, failure)
          : ImportReview(preview, error: failure);
    }
    changed();
  }

  Future<void> reconcile() async {
    final current = state;
    if (current is! ImportUncertain) return;
    try {
      final result = await service.reconcile(current.identity.idempotencyKey);
      if (!disposed && result != null) state = ImportComplete(result);
    } catch (error) {
      if (!disposed)
        state = ImportUncertain(
          current.preview,
          current.identity,
          safeFailure(error),
        );
    }
    changed();
  }

  @override
  void dispose() {
    _epoch++;
    final current = state;
    if (current is ImportReview) _discard(current.preview.id);
    // Saving/uncertain identities are not treated as cancellation of a commit.
    super.dispose();
  }
}

class AdminController extends SafeController {
  AdminController(this.api);
  final ManagementApi api;
  LoadState<ManagementSnapshot> state = const Loading();
  MutationState mutation = const MutationIdle();
  ChangePlan? plan;
  OperationView? activeOperation;
  ProductFailure? operationReadError;
  int _operationEpoch = 0;
  Timer? _poll;
  int _readEpoch = 0;
  int _sessionEpoch = 0;

  /// Remove prior session data without forgetting uncertain command identity.
  /// A late HTTP response from a logged-out session cannot repopulate the page.
  void forgetSession() {
    _sessionEpoch++;
    _readEpoch++;
    _operationEpoch++;
    _poll?.cancel();
    state = const LoadFailed(ProductFailure('AUTH_REQUIRED', '请登录管理服务。'));
    plan = null;
    activeOperation = null;
    operationReadError = null;
    final pending = mutation;
    if (pending is MutationRunning) {
      mutation = MutationUncertain(
        const ProductFailure(
          'SESSION_ENDED_DURING_COMMAND',
          '会话结束时操作结果尚未确认。',
          remediation: '使用原管理账号登录后查询原操作；不要重复提交。',
          outcomeUnknown: true,
        ),
        pending.identity,
      );
    } else if (pending is! MutationUncertain) {
      mutation = const MutationIdle();
    }
    changed();
  }

  Future<void> refresh() async {
    final epoch = ++_readEpoch;
    final old = state.previous;
    state = Loading(old);
    changed();
    try {
      final result = await api.snapshot();
      if (disposed || epoch != _readEpoch) return;
      state = Loaded(result);
      if (plan != null && plan!.baseRevision != result.revision) plan = null;
    } catch (error) {
      if (disposed || epoch != _readEpoch) return;
      state = LoadFailed(safeFailure(error), old);
    }
    changed();
  }

  Future<void> preview(
    Future<ChangePlan> Function(MutationIdentity) build,
  ) async {
    if (mutation.blocked || state is! Loaded<ManagementSnapshot>) return;
    final sessionEpoch = _sessionEpoch;
    final identity = identityFor(state.previous!.revision);
    mutation = MutationRunning('正在校验并生成变更计划', identity);
    changed();
    try {
      final result = await build(identity);
      if (disposed || sessionEpoch != _sessionEpoch) return;
      plan = result;
      mutation = const MutationIdle();
    } catch (error) {
      if (!disposed && sessionEpoch == _sessionEpoch)
        mutation = MutationFailed(safeFailure(error));
    }
    changed();
  }

  /// Adopt only a server-generated plan matching the currently read active revision.
  bool adoptPreparedPlan(ChangePlan candidate) {
    if (mutation.blocked ||
        state is! Loaded<ManagementSnapshot> ||
        candidate.baseRevision != state.previous!.revision ||
        !DateTime.now().isBefore(candidate.expiresAt))
      return false;
    plan = candidate;
    changed();
    return true;
  }

  void discardPlan() {
    if (!mutation.blocked) {
      plan = null;
      changed();
    }
  }

  Future<void> apply(String confirmation) async {
    final pending = plan;
    if (mutation.blocked ||
        pending == null ||
        state is! Loaded<ManagementSnapshot>)
      return;
    if (!DateTime.now().isBefore(pending.expiresAt) ||
        pending.baseRevision != state.previous!.revision) {
      plan = null;
      mutation = const MutationFailed(
        ProductFailure('PLAN_STALE', '计划已过期或服务器修订已变化，请重新预览。'),
      );
      changed();
      return;
    }
    if (confirmation != pending.confirmationPhrase) {
      mutation = const MutationFailed(
        ProductFailure('CONFIRMATION_MISMATCH', '确认文字与当前计划不一致。'),
      );
      changed();
      return;
    }
    final sessionEpoch = _sessionEpoch;
    final identity = identityFor(pending.baseRevision);
    mutation = MutationRunning('正在提交已确认计划', identity);
    changed();
    try {
      final result = await api.applyPlan(pending, confirmation, identity);
      if (disposed || sessionEpoch != _sessionEpoch) return;
      activeOperation = result;
      plan = null;
      mutation = MutationSucceeded('计划已提交；以服务端结果为准', activeOperation!.id);
      _schedulePoll();
    } catch (error) {
      if (disposed || sessionEpoch != _sessionEpoch) return;
      final failure = safeMutationFailure(error);
      mutation = failure.outcomeUnknown
          ? MutationUncertain(failure, identity)
          : MutationFailed(failure);
    }
    changed();
  }

  Future<void> reconcile() async {
    final pending = mutation;
    if (pending is! MutationUncertain) return;
    final sessionEpoch = _sessionEpoch;
    try {
      final operation = await api.reconcile(pending.identity.idempotencyKey);
      if (disposed || sessionEpoch != _sessionEpoch) return;
      if (operation != null) {
        activeOperation = operation;
        plan = null;
        mutation = MutationSucceeded('已找回原操作', operation.id);
        _schedulePoll();
      }
    } catch (error) {
      if (!disposed && sessionEpoch == _sessionEpoch)
        mutation = MutationUncertain(safeFailure(error), pending.identity);
    }
    changed();
  }

  Future<void> openOperation(String id) async {
    final epoch = ++_operationEpoch;
    _poll?.cancel();
    try {
      final result = await api.operation(id);
      if (disposed || epoch != _operationEpoch) return;
      activeOperation = result;
      operationReadError = null;
      _schedulePoll();
    } catch (error) {
      if (disposed || epoch != _operationEpoch) return;
      operationReadError = safeFailure(error);
      // Read failures cannot clear a pending/uncertain mutation or imply terminal.
      _poll = Timer(
        const Duration(seconds: 3),
        () => unawaited(openOperation(id)),
      );
    }
    changed();
  }

  void _schedulePoll() {
    _poll?.cancel();
    if (!disposed && activeOperation != null && !activeOperation!.terminal) {
      _poll = Timer(
        const Duration(seconds: 3),
        () => unawaited(openOperation(activeOperation!.id)),
      );
    }
  }

  Future<void> cancelOperation() async {
    final operation = activeOperation;
    if (operation == null ||
        !operation.cancellable ||
        mutation.blocked ||
        state is! Loaded<ManagementSnapshot>)
      return;
    final sessionEpoch = _sessionEpoch;
    final identity = identityFor(state.previous?.revision ?? 'unknown');
    mutation = MutationRunning('正在请求取消', identity);
    changed();
    try {
      final result = await api.cancelOperation(operation.id, identity);
      if (disposed || sessionEpoch != _sessionEpoch) return;
      activeOperation = result;
      mutation = MutationSucceeded('取消请求已提交；以服务端状态为准', operation.id);
      _schedulePoll();
    } catch (error) {
      if (disposed || sessionEpoch != _sessionEpoch) return;
      final failure = safeMutationFailure(error);
      mutation = failure.outcomeUnknown
          ? MutationUncertain(failure, identity)
          : MutationFailed(failure);
    }
    changed();
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }
}

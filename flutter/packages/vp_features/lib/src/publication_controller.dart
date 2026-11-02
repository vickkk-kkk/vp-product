import 'dart:async';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'controllers.dart';
import 'state.dart';

/// Only metadata enters observable state. Sensitive responses are transferred
/// directly to a short-lived presentation owner, never to this controller state.
enum PublicationAction {
  generateCredential,
  retireCredential,
  create,
  replace,
  revoke,
  issue,
  prepareListener,
}

class PendingPublicationAction {
  const PendingPublicationAction({
    required this.kind,
    required this.identity,
    required this.sessionEpoch,
    this.targetId,
  });
  final PublicationAction kind;
  final MutationIdentity identity;
  final int sessionEpoch;
  final String? targetId;
}

class IssueRecovery {
  const IssueRecovery({
    required this.publicationId,
    required this.identity,
    required this.message,
    this.metadata,
  });
  final String publicationId, message;
  final MutationIdentity identity;
  final PublishedSubscription? metadata;
}

class PublicationController extends SafeController {
  PublicationController(
    this.api,
    this.session, {
    bool Function()? otherMutationBlocked,
  }) : _otherMutationBlocked = otherMutationBlocked ?? _notBlocked {
    if (session is ManagementSessionEpoch) {
      _epochs = session as ManagementSessionEpoch;
      _epochs!.addSessionListener(_sessionChanged);
    }
  }
  final PublicationManagementApi api;
  final ManagementSession session;
  final bool Function() _otherMutationBlocked;
  static bool _notBlocked() => false;
  ManagementSessionEpoch? _epochs;
  int get sessionEpoch => _epochs?.sessionEpoch ?? 0;
  LoadState<PublicationWorkspace> state = const Loading();
  MutationState mutation = const MutationIdle();
  PendingPublicationAction? pending;
  PendingPublicationAction? _lastIssued;
  IssueRecovery? issueRecovery;
  ManagedCredential? generatedCredential;
  ChangePlan? preparedPlan;
  ProductFailure? recoveryReadError;
  String? notice;
  int completedActions = 0;
  Future<Object?> Function(MutationIdentity)? _retrySafeMetadata;
  void Function(Object?)? _acceptMetadata;
  int _readGeneration = 0;
  int _displayGeneration = 0;
  bool _foreground = true;
  bool get blocked =>
      mutation.blocked || issueRecovery != null || _otherMutationBlocked();
  bool get writable =>
      session.authenticated &&
      state is Loaded<PublicationWorkspace> &&
      !blocked;
  bool get canRetryOriginal =>
      mutation is MutationUncertain &&
      pending?.kind != PublicationAction.issue &&
      pending?.sessionEpoch == sessionEpoch &&
      _retrySafeMetadata != null &&
      session.authenticated;

  void setForeground(bool value) {
    _foreground = value;
    if (!value) _displayGeneration++;
  }

  void _sessionChanged() {
    _readGeneration++;
    _displayGeneration++;
    state = const LoadFailed(ProductFailure('AUTH_REQUIRED', '管理会话已变化，请重新读取。'));
    generatedCredential = null;
    _lastIssued = null;
    preparedPlan = null;
    recoveryReadError = null;
    notice = null;
    final recovery = issueRecovery;
    if (recovery != null)
      issueRecovery = IssueRecovery(
        publicationId: recovery.publicationId,
        identity: recovery.identity,
        message: recovery.message,
      );
    if (pending != null && mutation is MutationRunning) {
      mutation = MutationUncertain(
        const ProductFailure(
          'SESSION_CHANGED',
          '会话变化时操作结果尚未确认。',
          outcomeUnknown: true,
        ),
        pending!.identity,
      );
      if (pending!.kind == PublicationAction.issue) {
        issueRecovery = IssueRecovery(
          publicationId: pending!.targetId!,
          identity: pending!.identity,
          message: '可能已经签发链接，原链接不能重新取回。',
        );
      }
    }
    // A new login must never silently replay another principal's old mutation.
    _retrySafeMetadata = null;
    _acceptMetadata = null;
    changed();
  }

  @override
  void dispose() {
    _readGeneration++;
    _displayGeneration++;
    _epochs?.removeSessionListener(_sessionChanged);
    _retrySafeMetadata = null;
    _acceptMetadata = null;
    super.dispose();
  }

  Future<void> refresh() async {
    final generation = ++_readGeneration;
    final epoch = sessionEpoch;
    final previous = state.previous;
    state = Loading(previous);
    changed();
    try {
      final result = await api.readPublicationWorkspace();
      if (disposed ||
          generation != _readGeneration ||
          epoch != sessionEpoch ||
          !session.authenticated)
        return;
      state = Loaded(result);
    } catch (error) {
      if (disposed || generation != _readGeneration || epoch != sessionEpoch)
        return;
      state = LoadFailed(safeFailure(error), previous);
    }
    changed();
  }

  Future<void> _metadataAction(
    PublicationAction kind,
    String revision,
    Future<Object?> Function(MutationIdentity) action, {
    String? targetId,
    void Function(Object?)? accept,
  }) async {
    if (!writable) return;
    final identity = identityFor(revision);
    pending = PendingPublicationAction(
      kind: kind,
      identity: identity,
      sessionEpoch: sessionEpoch,
      targetId: targetId,
    );
    _retrySafeMetadata = action;
    _acceptMetadata = accept;
    await _runSafeMetadata();
  }

  Future<void> retryOriginal() async {
    if (!canRetryOriginal || _otherMutationBlocked()) return;
    await _runSafeMetadata();
  }

  Future<void> _runSafeMetadata() async {
    final original = pending!;
    final wasUnknown = mutation is MutationUncertain;
    notice = null;
    mutation = MutationRunning(switch (original.kind) {
      PublicationAction.generateCredential => '正在生成连接凭据',
      PublicationAction.retireCredential => '正在回收未使用凭据',
      PublicationAction.create => '正在创建发布内容',
      PublicationAction.replace => '正在重新发布',
      PublicationAction.revoke => '正在撤销订阅访问',
      PublicationAction.prepareListener => '正在保存草稿、校验并生成计划（尚未应用）',
      PublicationAction.issue => '正在签发访问链接',
    }, original.identity);
    changed();
    if (disposed ||
        original.sessionEpoch != sessionEpoch ||
        !session.authenticated)
      return;
    try {
      final result = await _retrySafeMetadata!(original.identity);
      if (disposed ||
          original.sessionEpoch != sessionEpoch ||
          !session.authenticated)
        return;
      _acceptMetadata?.call(result);
      completedActions++;
      mutation = const MutationIdle();
      notice = switch (original.kind) {
        PublicationAction.generateCredential => '连接凭据已保存在服务器；尚未启动监听。',
        PublicationAction.retireCredential => '未使用凭据已回收。',
        PublicationAction.create => '发布内容已创建，尚未签发访问链接。',
        PublicationAction.replace => '发布内容已更新。',
        PublicationAction.revoke => '订阅访问已撤销；已缓存节点凭据仍然有效。',
        PublicationAction.prepareListener => '草稿已校验，变更计划已生成；尚未应用。',
        PublicationAction.issue => '访问链接签发已处理。',
      };
      pending = null;
      _retrySafeMetadata = null;
      _acceptMetadata = null;
      changed();
      await refresh();
    } catch (error) {
      if (disposed ||
          original.sessionEpoch != sessionEpoch ||
          !session.authenticated)
        return;
      final failure = safeMutationFailure(error);
      mutation = failure.outcomeUnknown || wasUnknown
          ? MutationUncertain(failure, original.identity)
          : MutationFailed(failure);
      if (!failure.outcomeUnknown && !wasUnknown) {
        pending = null;
        _retrySafeMetadata = null;
        _acceptMetadata = null;
      }
      changed();
    }
  }

  Future<void> generateCredential() async {
    final current = state.previous;
    if (current == null || !current.supportsUuid) return;
    await _metadataAction(
      PublicationAction.generateCredential,
      '${current.activeRevision}',
      api.generateUuidCredential,
      accept: (result) => generatedCredential = result as ManagedCredential,
    );
  }

  Future<void> retire(ManagedCredential credential) => _metadataAction(
    PublicationAction.retireCredential,
    '${credential.revision}',
    (identity) => api.retireCredential(credential.id, identity),
    targetId: credential.id,
  );
  Future<void> create(PublicationDraft draft) async {
    final current = state.previous;
    if (current == null ||
        current.observedRevision != current.activeRevision ||
        current.activeRevision == 0)
      return;
    await _metadataAction(
      PublicationAction.create,
      '${current.activeRevision}',
      (identity) => api.createPublication(draft, identity),
    );
  }

  Future<void> replace(
    PublishedSubscription publication,
    PublicationDraft draft,
  ) async {
    final current = state.previous;
    if (current == null ||
        current.observedRevision != current.activeRevision ||
        current.activeRevision == 0)
      return;
    await _metadataAction(
      PublicationAction.replace,
      '${publication.revision}',
      (identity) => api.replacePublication(
        publication.id,
        draft,
        current.activeRevision,
        identity,
      ),
      targetId: publication.id,
    );
  }

  Future<void> revoke(PublishedSubscription publication) => _metadataAction(
    PublicationAction.revoke,
    '${publication.revision}',
    (identity) => api.revokePublicationToken(publication.id, identity),
    targetId: publication.id,
  );
  Future<void> prepareListener(
    NewUuidListenerInput input,
    ManagedCredential credential,
  ) async {
    final current = state.previous;
    if (current == null ||
        !current.supportsUuid ||
        !credential.kind.isUuid ||
        credential.state != ManagedCredentialState.available)
      return;
    if (!writable) return;
    preparedPlan = null;
    await _metadataAction(
      PublicationAction.prepareListener,
      '${current.activeRevision}',
      (identity) => api.prepareNewUuidListener(input, credential, identity),
      accept: (result) => preparedPlan = result as ChangePlan,
    );
  }

  /// Outcome recovery is read-only. It cannot turn into a secret reissue by itself.
  Future<void> readIssueMetadata() async {
    final recovery = issueRecovery;
    if (recovery == null || !session.authenticated) return;
    final epoch = sessionEpoch;
    recoveryReadError = null;
    changed();
    try {
      final result = await api.getPublication(recovery.publicationId);
      if (disposed || epoch != sessionEpoch || issueRecovery != recovery)
        return;
      issueRecovery = IssueRecovery(
        publicationId: recovery.publicationId,
        identity: recovery.identity,
        message: recovery.message,
        metadata: result,
      );
    } catch (error) {
      if (!disposed && epoch == sessionEpoch && issueRecovery == recovery)
        recoveryReadError = safeFailure(error);
    }
    changed();
  }

  void discardUndisplayedSecret(OneTimePublicationSecret result) {
    result.dispose();
    final issued = _lastIssued;
    if (disposed ||
        issued == null ||
        issued.sessionEpoch != sessionEpoch ||
        issued.targetId != result.publication.id)
      return;
    issueRecovery = IssueRecovery(
      publicationId: issued.targetId!,
      identity: issued.identity,
      message: '链接已签发，但展示页面已离开，链接已清除。需要时请明确轮换。',
    );
    mutation = MutationUncertain(
      const ProductFailure(
        'SECRET_DISPLAY_CLEARED',
        '链接展示已清除。',
        outcomeUnknown: true,
      ),
      issued.identity,
    );
    changed();
  }

  Future<OneTimePublicationSecret?> issue(
    PublishedSubscription publication,
    int expiresInSeconds, {
    required bool explicitlyConfirmed,
    bool replaceUnknown = false,
  }) async {
    if (!explicitlyConfirmed ||
        !session.authenticated ||
        !_foreground ||
        _otherMutationBlocked() ||
        !publication.enabled)
      return null;
    final current = state.previous;
    if (current == null ||
        current.activeRevision == 0 ||
        current.observedRevision != current.activeRevision ||
        publication.sourceRevision != current.activeRevision)
      return null;
    final recovery = issueRecovery;
    if (replaceUnknown) {
      if (mutation is MutationRunning ||
          recovery?.metadata?.id != publication.id ||
          recovery?.metadata?.revision != publication.revision)
        return null;
    } else if (!writable) {
      return null;
    }
    final identity = identityFor('${publication.revision}');
    final epoch = sessionEpoch;
    final display = _displayGeneration;
    pending = PendingPublicationAction(
      kind: PublicationAction.issue,
      identity: identity,
      sessionEpoch: epoch,
      targetId: publication.id,
    );
    mutation = MutationRunning('正在签发一次性展示链接', identity);
    changed();
    if (disposed || epoch != sessionEpoch || !session.authenticated)
      return null;
    if (!_foreground) {
      pending = null;
      mutation = const MutationFailed(
        ProductFailure(
          'SECRET_DISPLAY_NOT_ACTIVE',
          '页面已离开，未发送签发请求。',
          definitelyNotApplied: true,
        ),
      );
      changed();
      return null;
    }
    try {
      final result = await api.issuePublicationToken(
        publication.id,
        expiresInSeconds,
        identity,
      );
      if (disposed || epoch != sessionEpoch || !session.authenticated) {
        result.dispose();
        return null;
      }
      if (display != _displayGeneration ||
          !_foreground ||
          result.sessionEpoch != epoch) {
        result.dispose();
        issueRecovery = IssueRecovery(
          publicationId: publication.id,
          identity: identity,
          message: '链接已签发，但页面失焦，展示已清除。原链接不能重新取回。',
        );
        mutation = MutationUncertain(
          const ProductFailure(
            'SECRET_DISPLAY_CLEARED',
            '已清除一次性链接展示。',
            outcomeUnknown: true,
          ),
          identity,
        );
        changed();
        return null;
      }
      _lastIssued = pending;
      pending = null;
      issueRecovery = null;
      mutation = const MutationIdle();
      notice = '访问链接已签发，仅在专用窗口展示一次。';
      changed();
      // Caller owns result immediately; do not await unrelated metadata reads.
      unawaited(refresh());
      return result;
    } catch (error) {
      if (disposed || epoch != sessionEpoch) return null;
      final failure = safeMutationFailure(error);
      if (failure.outcomeUnknown ||
          failure.code == 'SECRET_RESULT_UNAVAILABLE') {
        issueRecovery = IssueRecovery(
          publicationId: publication.id,
          identity: identity,
          message: '可能已经签发链接，原链接不能重新取回。请先读取安全状态，再明确选择是否轮换。',
        );
        mutation = MutationUncertain(failure, identity);
      } else if (recovery != null) {
        issueRecovery = recovery;
        mutation = MutationUncertain(failure, recovery.identity);
      } else {
        pending = null;
        mutation = MutationFailed(failure);
      }
      changed();
      return null;
    }
  }
}

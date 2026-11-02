import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:vp_contracts/vp_contracts.dart';
import 'session.dart';
import 'wire.dart' as wire;
import 'publication_wire.dart' as publicationWire;

/// Same-origin, authenticated management transport. No node credentials, browser
/// localStorage, native libraries, system VPN actions, redirect or auto-retry.
class HttpManagementApi
    implements
        ManagementApi,
        ManagementSession,
        ManagementSessionEpoch,
        PublicationManagementApi {
  HttpManagementApi({
    required http.Client client,
    required Uri origin,
    this.timeout = const Duration(seconds: 20),
    this.maxResponseBytes = 8 * 1024 * 1024,
  }) : _client = client,
       _origin = Uri(
         scheme: origin.scheme,
         host: origin.host,
         port: origin.hasPort ? origin.port : null,
       ) {
    if (!const {'https', 'http'}.contains(_origin.scheme) ||
        _origin.host.isEmpty ||
        origin.userInfo.isNotEmpty) {
      throw ArgumentError('Management requires an HTTP(S) page origin.');
    }
    // HTTP is permitted only for isolated loopback development, never remote login.
    if (_origin.scheme == 'http' &&
        !const {'localhost', '127.0.0.1', '::1'}.contains(_origin.host)) {
      throw ArgumentError('Remote management requires HTTPS.');
    }
  }
  final http.Client _client;
  final Uri _origin;
  final Duration timeout;
  final int maxResponseBytes;
  String? _csrf;
  bool _closed = false;
  int _authEpoch = 0;
  final Set<void Function()> _sessionListeners = {};
  OneTimePublicationSecret? _issuedSecret;
  bool _issuingSecret = false;
  @override
  int get sessionEpoch => _authEpoch;
  @override
  void addSessionListener(void Function() listener) =>
      _sessionListeners.add(listener);
  @override
  void removeSessionListener(void Function() listener) =>
      _sessionListeners.remove(listener);
  int _invalidateSession({bool clearAuthentication = true}) {
    _authEpoch++;
    if (clearAuthentication) _csrf = null;
    _issuedSecret?.dispose();
    _issuedSecret = null;
    lastPreparedDraftId = null;
    for (final listener in List<void Function()>.of(_sessionListeners)) {
      listener();
    }
    return _authEpoch;
  }

  void _checkEpoch(int epoch, {bool mutation = false}) {
    if (_closed || _authEpoch != epoch) {
      throw ProductFailure(
        'SESSION_CHANGED',
        '管理会话已经改变。',
        outcomeUnknown: mutation,
        definitelyNotApplied: !mutation,
      );
    }
  }

  String? lastPreparedDraftId;
  @override
  bool get canAuthenticate => !_closed;
  @override
  bool get authenticated => _csrf != null && !_closed;
  @override
  String get originLabel => _origin.toString();

  @override
  Future<void> restoreSession() async {
    final epoch = _authEpoch;
    final session = wire.object(await _request('GET', '/api/v1/auth/session'));
    _acceptSession(epoch, session['csrfToken']);
  }

  @override
  Future<void> login(
    String username,
    String password, {
    String? secondFactor,
  }) async {
    final epoch = _invalidateSession();
    _csrf = null;
    final result = wire.object(
      await _request(
        'POST',
        '/api/v1/auth/login',
        body: {
          'username': username,
          'password': password,
          'secondFactor': secondFactor,
        },
        authenticatedMutation: false,
      ),
    );
    _acceptSession(epoch, result['csrfToken']);
  }

  @override
  Future<void> logout() async {
    _invalidateSession(clearAuthentication: false);
    try {
      await _request('POST', '/api/v1/auth/logout');
    } finally {
      _invalidateSession();
      _csrf = null;
    }
  }

  @override
  void close() {
    _closed = true;
    _invalidateSession();
    _csrf = null;
    _client.close();
    _sessionListeners.clear();
  }

  void _acceptSession(int epoch, Object? csrfToken) {
    if (_closed || epoch != _authEpoch) {
      throw const ProductFailure(
        'SESSION_CHANGED',
        '管理会话已经改变，请重新读取登录状态。',
        definitelyNotApplied: true,
      );
    }
    _csrf = _csrfToken(csrfToken);
  }

  Future<Object?> _request(
    String method,
    String path, {
    Object? body,
    String? expectedRequestId,
    String? ifMatch,
    bool authenticatedMutation = true,
    bool sensitiveResult = false,
  }) async {
    if (_closed)
      throw const ProductFailure(
        'CLOSED',
        '管理连接已关闭。',
        definitelyNotApplied: true,
      );
    final mutation = method != 'GET';
    final metadataPath =
        path.startsWith('/api/v1/credentials') ||
        path.startsWith('/api/v1/publications');
    final responseLimit = metadataPath && maxResponseBytes > 1024 * 1024
        ? 1024 * 1024
        : maxResponseBytes;
    final requestAuthEpoch = _authEpoch;
    if (!path.startsWith('/api/v1/') ||
        path.contains('?') ||
        path.contains('#') ||
        path.contains('..'))
      throw wire.malformed;
    if (mutation && authenticatedMutation && _csrf == null)
      throw const ProductFailure(
        'AUTH_REQUIRED',
        '请先登录管理账号。',
        definitelyNotApplied: true,
      );
    final request = http.Request(method, _origin.resolve(path))
      ..followRedirects = false;
    request.headers['Accept'] = 'application/json';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    if (mutation && authenticatedMutation)
      request.headers['X-VP-CSRF'] = _csrf!;
    if (ifMatch != null) request.headers['If-Match'] = '"$ifMatch"';
    try {
      final response = await _client.send(request).timeout(timeout);
      if (response.statusCode == 401 && requestAuthEpoch == _authEpoch) {
        _invalidateSession();
        _csrf = null;
      }
      if (response.contentLength != null &&
          response.contentLength! > responseLimit) {
        await response.stream.listen((_) {}).cancel();
        throw wire.malformed;
      }
      final bytes = <int>[];
      await for (final chunk in response.stream.timeout(timeout)) {
        if (bytes.length + chunk.length > responseLimit) throw wire.malformed;
        bytes.addAll(chunk);
      }
      if (!(response.headers['content-type'] ?? '').toLowerCase().startsWith(
        'application/json',
      ))
        throw wire.malformed;
      if (sensitiveResult &&
          (!(response.headers['cache-control'] ?? '')
                  .toLowerCase()
                  .split(',')
                  .map((s) => s.trim())
                  .contains('no-store') ||
              response.headers['referrer-policy'] != 'no-referrer'))
        throw wire.malformed;
      final envelope = wire.object(
        jsonDecode(utf8.decode(bytes, allowMalformed: false)),
      );
      wire.schema(envelope);
      wire.id(envelope['requestId']);
      if (expectedRequestId != null &&
          envelope['requestId'] != expectedRequestId)
        throw wire.malformed;
      final hasResult = envelope.containsKey('result');
      final hasError = envelope.containsKey('error');
      if (hasResult == hasError) throw wire.malformed;
      if (hasError)
        throw wire.productError(envelope['error'], mutation: mutation);
      if (response.statusCode < 200 || response.statusCode >= 300)
        throw wire.malformed;
      _checkEpoch(requestAuthEpoch, mutation: mutation);
      return envelope['result'];
    } catch (error) {
      if (error is ProductFailure)
        throw mutation ? safeMutationFailure(error) : error;
      // Network exceptions may contain URLs or response text. Never expose them.
      throw ProductFailure(
        'MANAGEMENT_TRANSPORT_FAILED',
        '无法确认管理服务的响应。',
        remediation: mutation ? '请查询原操作，不要再次提交。' : '检查同源管理服务、TLS 和网络，再重新读取。',
        retryable: !mutation,
        outcomeUnknown: mutation,
      );
    }
  }

  Map<String, Object?> _command(
    String method,
    Object payload,
    MutationIdentity identity,
  ) => {
    'schemaVersion': 1,
    'requestId': wire.id(identity.requestId),
    'idempotencyKey': wire.id(identity.idempotencyKey),
    'expectedRevision': wire.revision(int.tryParse(identity.expectedRevision)),
    'method': method,
    'payload': payload,
  };
  MutationIdentity _step(
    MutationIdentity identity,
    String suffix,
    String revision,
  ) => MutationIdentity(
    requestId: '${identity.requestId}_$suffix',
    idempotencyKey: '${identity.idempotencyKey}_$suffix',
    expectedRevision: revision,
  );

  @override
  Future<ManagementSnapshot> snapshot() async {
    if (!authenticated) await restoreSession();
    final values = await Future.wait([
      _request('GET', '/api/v1/build'),
      _request('GET', '/api/v1/capabilities'),
      _request('GET', '/api/v1/config'),
      _request('GET', '/api/v1/snapshot'),
    ]);
    final build = wire.object(values[0]);
    wire.schema(build);
    if (wire.array(build['requiredFeatures']).isNotEmpty) throw wire.malformed;
    final release = wire.object(build['release']);
    if (wire.object(release['api'])['major'] != 1) throw wire.malformed;
    final config = wire.object(values[2]);
    final observed = wire.object(values[3]);
    wire.schema(observed);
    final desiredRevision = wire.revision(config['revision']);
    if (wire.revision(observed['desiredRevision']) != desiredRevision)
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '读取时服务器修订发生变化，请重新读取。',
        retryable: true,
        definitelyNotApplied: true,
      );
    final desiredConfig = config['config'] == null
        ? null
        : wire.object(config['config']);
    if (desiredConfig != null) {
      wire.schema(desiredConfig);
      if (wire.revision(desiredConfig['minimumReaderVersion']) > 1)
        throw wire.malformed;
    }
    final observations = {
      for (final item in wire.array(observed['listeners']))
        wire.id(wire.object(item)['listenerId']): wire.object(item),
    };
    final actualRevision = observed['observedRevision'] == null
        ? null
        : wire.revision(observed['observedRevision']).toString();
    return ManagementSnapshot(
      developmentBuild: wire.boolean(build['development']),
      hostLabel: _origin.host,
      safeManagementOrigin: originLabel,
      revision: desiredRevision.toString(),
      observedRevision: actualRevision,
      // This is receipt time, labelled "读取于", never a fabricated probe timestamp.
      observedAt: DateTime.now().toUtc(),
      listeners: [
        for (final item
            in desiredConfig == null
                ? <Object?>[]
                : wire.array(desiredConfig['listeners']))
          _listener(
            wire.object(item),
            observations,
            desiredRevision.toString(),
            actualRevision,
          ),
      ],
      presets: _presets(wire.array(values[1]), release),
      operations: [
        for (final item in wire.array(observed['operations']))
          wire.operation(item),
      ],
    );
  }

  ListenerView _listener(
    Map<String, Object?> item,
    Map<String, Map<String, Object?>> observations,
    String revision,
    String? actual,
  ) {
    final id = wire.id(item['id']);
    final binding = wire.object(item['bind']);
    final status = observations[id];
    final requirements = wire.array(item['requirements']);
    return ListenerView(
      id: id,
      name: wire.string(item['name'], max: 512),
      presetKey: requirements.isEmpty
          ? '未声明模板'
          : requirements.map(wire.code).join(' · '),
      bind: wire.string(binding['address']),
      port: wire.port(binding['port']),
      desiredEnabled: wire.boolean(item['enabled']),
      observedState: status == null
          ? '尚未观测'
          : _listenerState(wire.code(status['status'])),
      desiredRevision: revision,
      observedRevision: actual,
      problem: status?['error'] == null
          ? null
          : wire.productError(status!['error'], mutation: false),
    );
  }

  List<PresetView> _presets(
    List<Object?> values,
    Map<String, Object?> release,
  ) {
    final grouped = <String, List<Map<String, Object?>>>{};
    for (final value in values) {
      final item = wire.object(value);
      if (item['direction'] != 'inbound' || item['platform'] != 'linux-service')
        continue;
      grouped.putIfAbsent(wire.code(item['key']), () => []).add(item);
    }
    return [
      for (final entry in grouped.entries)
        _preset(entry.key, entry.value, release),
    ];
  }

  PresetView _preset(
    String key,
    List<Map<String, Object?>> items,
    Map<String, Object?> release,
  ) {
    final evidence = <String>{};
    var certified = true;
    for (final item in items) {
      final identity = wire.object(item['releaseIdentity']);
      final ids = wire.array(item['evidenceIds']).map(wire.id).toList();
      evidence.addAll(ids);
      certified &=
          item['status'] == 'certified' &&
          ids.isNotEmpty &&
          identity['evidenceManifestHash'] != null &&
          identity['patchsetHash'] != null &&
          identity['releaseId'] == release['releaseId'];
    }
    final first = items.first;
    return PresetView(
      key: key,
      name: key.replaceFirst('preset.', ''),
      description:
          '${wire.code(first['protocol'])} · ${wire.code(first['transport'])} · ${wire.code(first['security'])}',
      capability: CapabilityView(
        key: key,
        label: key,
        status: certified
            ? CapabilityStatus.certified
            : CapabilityStatus.pending,
        reason: certified
            ? '当前发行组合所列路径均有认证记录。'
            : '尚未取得完整认证：${items.map((item) => wire.code(item['reason'])).toSet().join('、')}',
        evidenceIds: List.unmodifiable(evidence),
      ),
    );
  }

  @override
  Future<ChangePlan> planListener(
    ListenerDraft draft,
    MutationIdentity command,
  ) async {
    if (draft.listenerId == null)
      throw const ProductFailure(
        'LISTENER_FIELDS_REQUIRED',
        '新监听还需要完整的协议、用户和证书参数。',
        remediation: '当前编辑器不能创建不完整监听。请使用完整草稿流程。',
        definitelyNotApplied: true,
      );
    final active = wire.object(await _request('GET', '/api/v1/config'));
    if (wire.revision(active['revision']).toString() !=
            command.expectedRevision ||
        active['config'] == null)
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '活动配置已变化，请重新读取。',
        definitelyNotApplied: true,
      );
    final config = wire.object(active['config']);
    _writableConfig(config);
    final listeners = wire.array(config['listeners']).map(wire.object).toList();
    final index = listeners.indexWhere(
      (item) => item['id'] == draft.listenerId,
    );
    if (index < 0)
      throw const ProductFailure(
        'CONFIG_INVALID',
        '找不到待编辑监听。',
        definitelyNotApplied: true,
      );
    final old = listeners[index];
    final oldBind = wire.object(old['bind']);
    listeners[index] = {
      ...old,
      'name': draft.name,
      'enabled': draft.enabled,
      'bind': {...oldBind, 'address': draft.bind, 'port': draft.port},
    };
    final changes = [
      PlanChange(
        field: '名称',
        before: wire.string(old['name']),
        after: draft.name,
      ),
      PlanChange(
        field: '绑定地址',
        before: '${oldBind['address']}:${oldBind['port']}',
        after: '${draft.bind}:${draft.port}',
      ),
      PlanChange(
        field: '期望启用',
        before: old['enabled'] == true ? '启用' : '停用',
        after: draft.enabled ? '启用' : '停用',
      ),
    ];
    return _preparePlan({...config, 'listeners': listeners}, changes, command);
  }

  @override
  Future<ChangePlan> planDeleteListener(
    String id,
    MutationIdentity command,
  ) async {
    final active = wire.object(await _request('GET', '/api/v1/config'));
    if (wire.revision(active['revision']).toString() !=
            command.expectedRevision ||
        active['config'] == null)
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '活动配置已变化，请重新读取。',
        definitelyNotApplied: true,
      );
    final config = wire.object(active['config']);
    _writableConfig(config);
    final listeners = wire.array(config['listeners']).map(wire.object).toList();
    final matches = listeners.where((item) => item['id'] == id).toList();
    if (matches.length != 1)
      throw const ProductFailure(
        'CONFIG_INVALID',
        '找不到待删除监听。',
        definitelyNotApplied: true,
      );
    listeners.removeWhere((item) => item['id'] == id);
    return _preparePlan(
      {...config, 'listeners': listeners},
      [
        PlanChange(
          field: '监听',
          before: wire.string(matches.single['name']),
          after: '删除',
        ),
      ],
      command,
    );
  }

  Future<ChangePlan> _preparePlan(
    Map<String, Object?> config,
    List<PlanChange> changes,
    MutationIdentity command, {
    bool verifyDraftContents = true,
  }) async {
    try {
      return await _preparePlanSteps(
        config,
        changes,
        command,
        verifyDraftContents: verifyDraftContents,
      );
    } catch (error) {
      throw safeMutationFailure(error);
    }
  }

  Future<ChangePlan> _preparePlanSteps(
    Map<String, Object?> config,
    List<PlanChange> changes,
    MutationIdentity command, {
    required bool verifyDraftContents,
  }) async {
    final create = _step(command, 'draft', command.expectedRevision);
    final draft = wire.object(
      await _request(
        'POST',
        '/api/v1/drafts',
        body: _command('draft_create', config, create),
        expectedRequestId: create.requestId,
      ),
    );
    final draftId = wire.id(draft['id']);
    lastPreparedDraftId = draftId;
    if (verifyDraftContents &&
        (wire.revision(draft['baseRevision']).toString() !=
                command.expectedRevision ||
            !_sameJson(config, draft['config']))) {
      throw const ProductFailure(
        'DRAFT_CHANGED',
        '草稿内容与原始请求不一致，已停止校验与计划生成。',
        outcomeUnknown: true,
      );
    }
    final validate = _step(
      command,
      'validate',
      wire.revision(draft['revision']).toString(),
    );
    try {
      await _request(
        'POST',
        '/api/v1/drafts/$draftId/validate',
        body: _command('validate', const {}, validate),
        expectedRequestId: validate.requestId,
      );
      final planIdentity = _step(command, 'plan', command.expectedRevision);
      final result = wire.object(
        await _request(
          'POST',
          '/api/v1/plans',
          body: _command('plan_create', {'draftId': draftId}, planIdentity),
          expectedRequestId: planIdentity.requestId,
        ),
      );
      final planId = wire.id(result['id']);
      return ChangePlan(
        id: planId,
        hash: wire.hash(result['planHash']),
        baseRevision: wire.revision(result['baseRevision']).toString(),
        target: _origin.host,
        changes: changes,
        impacts: [
          wire.code(result['impact']),
          ...wire.array(result['requiredPermissions']).map(wire.code),
        ],
        recovery: result['recoveryAvailable'] == true
            ? '服务端声明可恢复；条件：${wire.code(result['recoveryDescriptionKey'])}'
            : '服务端未提供可用恢复路径。',
        expiresAt: DateTime.fromMillisecondsSinceEpoch(
          wire.timestamp(result['expiresAt']),
          isUtc: true,
        ),
        confirmationPhrase: '应用计划 $planId',
      );
    } on ProductFailure catch (failure) {
      throw ProductFailure(
        failure.code,
        failure.message,
        remediation: '草稿 $draftId 已保存，但尚未应用。${failure.remediation ?? ''}',
        diagnosticId: failure.diagnosticId,
        outcomeUnknown: failure.outcomeUnknown,
        definitelyNotApplied: failure.definitelyNotApplied,
      );
    }
  }

  @override
  Future<OperationView> applyPlan(
    ChangePlan plan,
    String confirmation,
    MutationIdentity command,
  ) async {
    if (confirmation != plan.confirmationPhrase ||
        !DateTime.now().isBefore(plan.expiresAt))
      throw const ProductFailure(
        'CONFIRMATION_REQUIRED',
        '计划确认不匹配或已经过期。',
        definitelyNotApplied: true,
      );
    return wire.operation(
      await _request(
        'POST',
        '/api/v1/plans/${wire.id(plan.id)}/apply',
        body: _command('plan_apply', {
          'planHash': wire.hash(plan.hash),
          'confirmed': true,
        }, command),
        expectedRequestId: command.requestId,
      ),
    );
  }

  @override
  Future<OperationView> operation(String id) async => wire.operation(
    await _request('GET', '/api/v1/operations/${wire.id(id)}'),
  );
  @override
  Future<OperationView?> reconcile(String idempotencyKey) async {
    // 404/unavailable/timeout is not proof of non-application and stays blocked.
    return wire.operation(
      await _request(
        'GET',
        '/api/v1/operations/by-idempotency/${wire.id(idempotencyKey)}',
      ),
    );
  }

  @override
  Future<OperationView> cancelOperation(
    String id,
    MutationIdentity command,
  ) async => wire.operation(
    await _request(
      'POST',
      '/api/v1/operations/${wire.id(id)}/cancel',
      body: _command('operation_cancel', const {}, command),
      expectedRequestId: command.requestId,
    ),
  );
  Future<T> _publicationMutation<T>(
    Future<Object?> request,
    T Function(Object?) decode,
  ) async {
    try {
      return decode(await request);
    } catch (error) {
      throw safeMutationFailure(error);
    }
  }

  @override
  Future<CredentialInventoryView> credentialInventory() async =>
      publicationWire.inventory(await _request('GET', '/api/v1/credentials'));

  @override
  Future<ManagedCredential> generateUuidCredential(
    MutationIdentity command,
  ) async => _publicationMutation(
    _request(
      'POST',
      '/api/v1/credentials',
      body: _command('credential_create', {
        'kind': {'kind': 'uuid'},
        'confirmGenerate': true,
      }, command),
      expectedRequestId: command.requestId,
    ),
    (raw) {
      final result = publicationWire.credential(raw);
      if (!result.kind.isUuid) throw wire.malformed;
      return result;
    },
  );

  @override
  Future<ManagedCredential> retireCredential(
    String id,
    MutationIdentity command,
  ) async => _publicationMutation(
    _request(
      'POST',
      '/api/v1/credentials/${wire.id(id)}/retire',
      body: _command('credential_retire', {'confirmRetire': true}, command),
      expectedRequestId: command.requestId,
      ifMatch: command.expectedRevision,
    ),
    (raw) {
      final result = publicationWire.credential(raw);
      if (result.id != id) throw wire.malformed;
      return result;
    },
  );

  @override
  Future<List<PublishedSubscription>> publications() async => publicationWire
      .publications(await _request('GET', '/api/v1/publications'));

  @override
  Future<PublishedSubscription> getPublication(String id) async {
    final result = publicationWire.publication(
      await _request('GET', '/api/v1/publications/${wire.id(id)}'),
    );
    if (result.id != id) throw wire.malformed;
    return result;
  }

  @override
  Future<PublishedSubscription> createPublication(
    PublicationDraft draft,
    MutationIdentity command,
  ) async => _publicationMutation(
    _request(
      'POST',
      '/api/v1/publications',
      body: _command(
        'publication_create',
        publicationWire.draft(draft),
        command,
      ),
      expectedRequestId: command.requestId,
    ),
    publicationWire.publication,
  );

  @override
  Future<PublishedSubscription> replacePublication(
    String id,
    PublicationDraft draft,
    int sourceRevision,
    MutationIdentity command,
  ) async => _publicationMutation(
    _request(
      'PUT',
      '/api/v1/publications/${wire.id(id)}',
      body: _command('publication_replace', {
        ...publicationWire.draft(draft),
        'sourceRevision': publicationWire.positive(sourceRevision),
      }, command),
      expectedRequestId: command.requestId,
      ifMatch: command.expectedRevision,
    ),
    (raw) {
      final result = publicationWire.publication(raw);
      if (result.id != id) throw wire.malformed;
      return result;
    },
  );

  @override
  Future<OneTimePublicationSecret> issuePublicationToken(
    String id,
    int expiresInSeconds,
    MutationIdentity command,
  ) async {
    if (expiresInSeconds < 300 || expiresInSeconds > 2592000)
      throw const ProductFailure(
        'CONFIG_INVALID',
        '链接有效期必须在 5 分钟至 30 天之间。',
        definitelyNotApplied: true,
      );
    if (_issuingSecret)
      throw const ProductFailure(
        'OPERATION_IN_PROGRESS',
        '另一个签发请求仍在处理中。',
        definitelyNotApplied: true,
      );
    _issuingSecret = true;
    try {
      final epoch = _authEpoch;
      _issuedSecret?.dispose();
      _issuedSecret = null;
      final raw = await _request(
        'POST',
        '/api/v1/publications/${wire.id(id)}/token',
        body: _command('publication_token_issue', {
          'confirmIssueSecretUrl': true,
          'expiresInSeconds': expiresInSeconds,
        }, command),
        expectedRequestId: command.requestId,
        ifMatch: command.expectedRevision,
        sensitiveResult: true,
      );
      _checkEpoch(epoch, mutation: true);
      final result = publicationWire.issued(raw, id, epoch, _origin);
      _issuedSecret = result;
      return result;
    } catch (error) {
      throw safeMutationFailure(error);
    } finally {
      _issuingSecret = false;
    }
  }

  @override
  Future<PublishedSubscription> revokePublicationToken(
    String id,
    MutationIdentity command,
  ) async {
    _issuedSecret?.dispose();
    _issuedSecret = null;
    return _publicationMutation(
      _request(
        'DELETE',
        '/api/v1/publications/${wire.id(id)}/token',
        body: _command('publication_token_revoke', {
          'confirmRevokeAccess': true,
        }, command),
        expectedRequestId: command.requestId,
        ifMatch: command.expectedRevision,
      ),
      (raw) {
        final result = publicationWire.publication(raw);
        if (result.id != id) throw wire.malformed;
        return result;
      },
    );
  }

  @override
  Future<PublicationWorkspace> readPublicationWorkspace() async {
    if (!authenticated) await restoreSession();
    final epoch = _authEpoch;
    final result = await Future.wait<Object?>([
      _request('GET', '/api/v1/config'),
      _request('GET', '/api/v1/snapshot'),
      _request('GET', '/api/v1/credentials'),
      _request('GET', '/api/v1/publications'),
      _request('GET', '/api/v1/build'),
      _request('GET', '/api/v1/capabilities'),
    ]);
    _checkEpoch(epoch);
    final active = wire.object(result[0]);
    final observation = wire.object(result[1]);
    wire.schema(observation);
    final revision = wire.revision(active['revision']);
    if (revision != wire.revision(observation['desiredRevision']))
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '读取时服务器配置发生变化，请重新读取。',
        retryable: true,
        definitelyNotApplied: true,
      );
    final observed = observation['observedRevision'] == null
        ? null
        : wire.revision(observation['observedRevision']);
    final build = wire.object(result[4]);
    wire.schema(build);
    final release = wire.object(build['release']);
    if (wire.array(build['requiredFeatures']).isNotEmpty ||
        wire.object(release['api'])['major'] != 1)
      throw wire.malformed;
    final presets = _presets(wire.array(result[5]), release);
    final inventory = publicationWire.inventory(result[2]);
    final candidates = <PublicationSourceCandidate>[];
    final statuses = <String, Map<String, Object?>>{};
    for (final raw in wire.array(observation['listeners'])) {
      final item = wire.object(raw);
      final id = wire.id(item['listenerId']);
      if (statuses.containsKey(id)) throw wire.malformed;
      statuses[id] = item;
    }
    if (active['config'] != null) {
      final config = wire.object(active['config']);
      _writableConfig(config);
      for (final raw in wire.array(config['listeners'])) {
        final listener = wire.object(raw);
        wire.schema(listener);
        final id = wire.id(listener['id']);
        final protocol = wire.object(listener['protocol']);
        if (protocol['kind'] != 'proxy')
          continue; // Direct is not a credential-bearing subscription source.
        final protocolModel = wire.object(protocol['protocol']);
        final protocolKind = wire.code(protocolModel['kind']);
        final transport = wire.code(wire.object(listener['transport'])['kind']);
        final security = wire.code(wire.object(listener['security'])['kind']);
        if (!const {
              'tuic',
              'trojan',
              'hysteria2',
              'vmess',
              'shadowsocks',
              'vless',
              'anytls',
              'socks5',
            }.contains(protocolKind) ||
            !const {
              'tcp',
              'ws',
              'http',
              'h2',
              'http_upgrade',
              'quic',
            }.contains(transport) ||
            !const {'none', 'tls', 'reality'}.contains(security))
          throw wire.malformed;
        final bind = wire.object(listener['bind']);
        final status = statuses[id];
        final forwarding = status == null
            ? null
            : wire.object(status['forwarding']);
        final proof =
            status != null &&
            status['error'] == null &&
            wire.revision(status['generation']) > 0 &&
            status['status'] == 'ready' &&
            status['bound'] == true &&
            status['authenticationLoaded'] == true &&
            forwarding?['status'] == 'passed' &&
            forwarding?['evidenceId'] != null &&
            forwarding?['observedAt'] != null;
        if (forwarding?['evidenceId'] != null)
          wire.id(forwarding!['evidenceId']);
        if (forwarding?['observedAt'] != null)
          wire.timestamp(forwarding!['observedAt']);
        for (final rawUser in wire.array(protocol['users'])) {
          final user = wire.object(rawUser);
          publicationWire.secretRef(user['credentialRef']);
          final enabled =
              wire.boolean(listener['enabled']) &&
              wire.boolean(user['enabled']);
          final matching = revision > 0 && observed == revision;
          final exportable =
              transport == 'tcp' &&
              security == 'none' &&
              ((protocolKind == 'vless' && protocolModel['flow'] == null) ||
                  const {'vmess', 'shadowsocks'}.contains(protocolKind));
          final selectable = enabled && matching && proof && exportable;
          candidates.add(
            PublicationSourceCandidate(
              listenerId: id,
              listenerName: wire.string(listener['name']),
              userId: wire.id(user['id']),
              protocol: protocolKind,
              transport: transport,
              securityKind: security,
              bindAddress: wire.string(bind['address']),
              bindPort: wire.port(bind['port']),
              selectable: selectable,
              reason: !enabled
                  ? '监听或用户已停用。'
                  : !exportable
                  ? '当前发布器暂不支持此协议、传输或安全映射；这不是协议认证结论。'
                  : !matching
                  ? '配置修订尚未得到实际运行确认。'
                  : !proof
                  ? '监听尚无已加载认证、绑定与转发的实际观测。'
                  : '来自当前已观测配置；发布时仍由服务器重新验证。',
            ),
          );
        }
      }
    }
    return PublicationWorkspace(
      developmentBuild: wire.boolean(build['development']),
      presets: presets,
      activeRevision: revision,
      observedRevision: observed,
      credentials: inventory.credentials,
      supportedKinds: inventory.supportedKinds,
      sources: candidates,
      publications: publicationWire.publications(result[3]),
    );
  }

  @override
  Future<ChangePlan> prepareNewUuidListener(
    NewUuidListenerInput input,
    ManagedCredential credential,
    MutationIdentity command,
  ) async {
    if (!const {'127.0.0.1', '::1'}.contains(input.bindAddress))
      throw const ProductFailure(
        'CONFIG_UNSUPPORTED',
        '当前无传输加密向导仅用于明确的回环开发监听。',
        definitelyNotApplied: true,
      );
    if (!credential.kind.isUuid ||
        credential.state != ManagedCredentialState.available)
      throw const ProductFailure(
        'CONFIG_INVALID',
        '请选择可用的 UUID 连接凭据。',
        definitelyNotApplied: true,
      );
    late final String listenerId, userId, listenerName, bindAddress;
    late final int bindPort;
    try {
      listenerId = wire.id(input.listenerId);
      userId = wire.id(input.userId);
      listenerName = publicationWire.label(input.name);
      bindAddress = publicationWire.numericBind(input.bindAddress);
      bindPort = wire.port(input.port);
    } catch (_) {
      throw const ProductFailure(
        'CONFIG_INVALID',
        '请检查监听名称、标识和端口。',
        definitelyNotApplied: true,
      );
    }

    final epoch = _authEpoch;
    final inventory = await credentialInventory();
    _checkEpoch(epoch);
    final found = inventory.credentials.where(
      (c) =>
          c.id == credential.id &&
          c.revision == credential.revision &&
          c.secretRef == credential.secretRef &&
          c.kind.isUuid &&
          c.state == ManagedCredentialState.available,
    );
    if (found.length != 1)
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '连接凭据已经变化，请重新读取。',
        definitelyNotApplied: true,
      );
    final active = wire.object(await _request('GET', '/api/v1/config'));
    _checkEpoch(epoch);
    if (wire.revision(active['revision']).toString() !=
        command.expectedRevision)
      throw const ProductFailure(
        'REVISION_CONFLICT',
        '活动配置已变化，请重新读取。',
        definitelyNotApplied: true,
      );
    final config = active['config'] == null
        ? <String, Object?>{
            'schemaVersion': 1,
            'minimumReaderVersion': 1,
            'nodes': <Object?>[],
            'subscriptions': <Object?>[],
            'listeners': <Object?>[],
          }
        : wire.object(active['config']);
    _writableConfig(config);
    final listeners = wire.array(config['listeners']).map(wire.object).toList();
    if (listeners.any((l) => l['id'] == listenerId))
      throw const ProductFailure(
        'CONFIG_INVALID',
        '监听标识已经存在。',
        definitelyNotApplied: true,
      );
    final listener = <String, Object?>{
      'schemaVersion': 1,
      'id': listenerId,
      'name': listenerName,
      'enabled': true,
      'bind': {'address': bindAddress, 'port': bindPort},
      'protocol': {
        'kind': 'proxy',
        'protocol': {'kind': 'vless', 'flow': null},
        'users': [
          {
            'id': userId,
            'credentialRef': publicationWire.secretRef(credential.secretRef),
            'enabled': true,
          },
        ],
      },
      'transport': {'kind': 'tcp'},
      'security': {'kind': 'none'},
      'requirements': <String>[],
    };
    // The server compiler owns capability gating. This creates only a candidate,
    // never assumes a UUID generator makes VLESS/TCP/None certified or started.
    return _preparePlan(
      {
        ...config,
        'listeners': [...listeners, listener],
      },
      [
        PlanChange(field: '新增监听', before: '无', after: input.name),
        PlanChange(
          field: '绑定地址',
          before: '无',
          after: '${input.bindAddress}:${input.port}',
        ),
        const PlanChange(
          field: '连接方式',
          before: '无',
          after: 'VLESS · TCP · 无传输加密',
        ),
        PlanChange(
          field: '连接凭据',
          before: '无',
          after: '已生成的托管 UUID（${credential.id}）',
        ),
      ],
      command,
      verifyDraftContents: true,
    );
  }
}

String _csrfToken(Object? value) {
  final token = wire.string(value, max: 512);
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(token)) throw wire.malformed;
  return token;
}

String _listenerState(String value) => switch (value) {
  'configured' => '已配置，尚未启用',
  'disabled' => '已停用',
  'starting' => '正在启动',
  'ready' => '监听已就绪（不代表外网已验证）',
  'degraded' => '运行受限',
  'failed' => '运行失败',
  'stopped' => '已停止',
  _ => throw wire.malformed,
};

void _writableConfig(Map<String, Object?> config) {
  wire.schema(config);
  if (wire.revision(config['minimumReaderVersion']) != 1) throw wire.malformed;
}

/// Structural comparison of bounded JSON, without accepting a changed draft on
/// same-key replay or relying on map insertion order.
bool _sameJson(Object? a, Object? b) {
  if (a is Map<String, Object?> && b is Map<String, Object?>) {
    return a.length == b.length &&
        a.keys.every((key) => b.containsKey(key) && _sameJson(a[key], b[key]));
  }
  if (a is List<Object?> && b is List<Object?>) {
    return a.length == b.length &&
        List<bool>.generate(
          a.length,
          (index) => _sameJson(a[index], b[index]),
        ).every((value) => value);
  }
  return a == b;
}

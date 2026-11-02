"""Management-secret consumers; shared control is the only issuer and writer.

Ordinary output is metadata only. One-time subscription URLs have one explicit
terminal-only path, no file/JSON fallback, retries, local tokens or URI encoders.
"""
import copy
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from vp_install import InstallError, require, read_regular, strict_json, digest
from vp_form import SchemaForm

PREFIX = '/api/v1'
ACTIONS = ('credentials', 'credential-create', 'credential-retire', 'publications',
           'publication', 'publication-create', 'publication-update', 'publication-republish',
           'publication-issue', 'publication-rotate', 'publication-revoke', 'manage-subscriptions')
MAX_COUNTER = 9007199254740991
REVOCATION_NOTICE = ('撤销/轮换/到期仅阻止以后下载订阅；已下载的节点凭据和已有连接不会因此失效。'
                     '撤销节点访问须另行通过 draft → validate → plan → apply 更改用户权限。')
UNKNOWN_NOTICE = ('签发结果不明或一次性结果已不可取回；未自动重发、未生成新请求键。'
                  '先查看安全元数据；旧链接可能已签发。需要新链接时，核对当前 revision 后'
                  '明确执行 publication-rotate 并使用新请求键，旧链接将在成功轮换后失效。')


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected),
            'unsupported/missing shared metadata fields; no output or substitution')


def ident(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value), 'valid shared ID required')
    return value


def counter(value, minimum=0):
    require(type(value) is int and minimum <= value <= MAX_COUNTER, 'invalid shared revision/timestamp')
    return value


def metadata_only(value, depth=0):
    """Defense in depth before any ordinary output, including unexpected envelopes."""
    require(depth <= 32, 'metadata nesting limit')
    if isinstance(value, dict):
        for key, child in value.items():
            require(key not in ('subscriptionUrl', 'password', 'privateKey', 'accessToken', 'authToken'),
                    'sensitive response refused outside explicit one-time terminal display')
            if key == 'token':
                require(isinstance(child, dict), 'raw token is not metadata')
            metadata_only(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            metadata_only(child, depth + 1)
    elif isinstance(value, str):
        require('/subscriptions/v1/' not in value, 'subscription URL refused in ordinary metadata')


def emit(value):
    metadata_only(value)
    print(json.dumps(value, indent=2, ensure_ascii=True))


def credential(value):
    keys(value, ('schemaVersion', 'id', 'revision', 'secretRef', 'kind', 'createdAt', 'state', 'displayKey'))
    require(value['schemaVersion'] == 1, 'unsupported credential schema')
    ident(value['id']); counter(value['revision'], 1); counter(value['createdAt'])
    require(isinstance(value['secretRef'], str) and re.fullmatch(r'secret:[A-Za-z0-9_-]{1,128}', value['secretRef']),
            'invalid managed credential reference')
    require(value['state'] in ('available', 'retired'), 'unsupported credential state')
    require(value['displayKey'] == ('credential.managed' if value['state'] == 'available' else 'credential.retired'),
            'inconsistent credential state')
    kind(value['kind']); metadata_only(value)
    return value


def kind(value):
    require(isinstance(value, dict), 'invalid credential kind')
    tag = value.get('kind')
    require(tag in ('uuid', 'password', 'shadowsocks', 'username_password', 'uuid_password'), 'unsupported credential kind')
    keys(value, ('kind', 'method') if tag == 'shadowsocks' else ('kind',))
    if tag == 'shadowsocks':
        require(value['method'] in ('aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
                'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                '2022-blake3-chacha20-poly1305'), 'unsupported shared cipher')


def inventory(api):
    value = api.request('GET', PREFIX + '/credentials')
    keys(value, ('schemaVersion', 'supportedKinds', 'credentials'))
    require(value['schemaVersion'] == 1 and isinstance(value['credentials'], list) and
            len(value['credentials']) <= 128 and isinstance(value['supportedKinds'], list) and
            len(value['supportedKinds']) <= 11, 'unsupported credential inventory')
    for item in value['supportedKinds']:
        kind(item)
    for item in value['credentials']:
        credential(item)
    return value


def source(value):
    # Shape checks prevent accidental secret fields from becoming metadata. Full
    # semantic/export/security validation still belongs to shared control/codec.
    keys(value, ('listenerId', 'userId', 'endpoint', 'clientSecurity'))
    ident(value['listenerId']); ident(value['userId'])
    keys(value['endpoint'], ('host', 'port'))
    endpoint = value['endpoint']
    require(isinstance(endpoint['host'], str) and 1 <= len(endpoint['host']) <= 253 and
            not any(c.isspace() or ord(c) < 32 for c in endpoint['host']), 'invalid explicit endpoint')
    require(type(endpoint['port']) is int and 1 <= endpoint['port'] <= 65535, 'invalid explicit endpoint port')
    security = value['clientSecurity']
    require(isinstance(security, dict), 'invalid client security')
    tag = security.get('kind')
    fields = {'none': ('kind',),
              'tls': ('kind', 'serverName', 'alpn', 'trust', 'clientHelloFingerprint'),
              'reality': ('kind', 'serverName', 'publicKey', 'shortId', 'clientHelloFingerprint')}
    require(tag in fields, 'unknown client security; never substituted with none')
    keys(security, fields[tag])
    if tag == 'tls':
        trust = security['trust']
        require(isinstance(trust, dict), 'invalid TLS trust')
        trust_fields = {'system': ('kind',), 'custom_ca': ('kind', 'certificateRef'), 'spki_sha256': ('kind', 'pins')}
        require(trust.get('kind') in trust_fields, 'unknown TLS trust; no insecure fallback')
        keys(trust, trust_fields[trust['kind']])
    metadata_only(value)
    return value


def publication(value):
    keys(value, ('schemaVersion', 'id', 'revision', 'name', 'enabled', 'format', 'sourceRevision',
                 'sources', 'createdAt', 'updatedAt', 'token', 'lastSuccessfulReadAt'))
    require(value['schemaVersion'] == 1, 'unsupported publication schema')
    ident(value['id']); counter(value['revision'], 1); counter(value['sourceRevision'], 1)
    publication_fields(value)
    counter(value['createdAt']); counter(value['updatedAt'])
    if value['lastSuccessfulReadAt'] is not None:
        counter(value['lastSuccessfulReadAt'])
    token = value['token']
    keys(token, ('state', 'version', 'issuedAt', 'expiresAt'))
    require(token['state'] in ('not_issued', 'active', 'revoked', 'expired'), 'unsupported token state')
    counter(token['version'])
    for field in ('issuedAt', 'expiresAt'):
        if token[field] is not None:
            counter(token[field])
    if token['state'] == 'not_issued':
        require(token['version'] == 0 and token['issuedAt'] is None and token['expiresAt'] is None, 'invalid token metadata')
    else:
        require(token['version'] > 0 and type(token['issuedAt']) is int and type(token['expiresAt']) is int and
                token['issuedAt'] < token['expiresAt'], 'invalid token expiry metadata')
    require(value['enabled'] or token['state'] != 'active', 'disabled publication has active token')
    metadata_only(value)
    return value


def publication_fields(value):
    require(isinstance(value['name'], str) and 1 <= len(value['name'].strip()) <= 128 and
            not any(ord(c) < 32 or ord(c) == 127 for c in value['name']), 'invalid publication name')
    require(type(value['enabled']) is bool and value['format'] == 'uri_list', 'unsupported publication format/enabled')
    require(isinstance(value['sources'], list) and 1 <= len(value['sources']) <= 32, 'publication requires 1..32 sources')
    seen = set()
    for item in value['sources']:
        source(item)
        pair = (item['listenerId'], item['userId'])
        require(pair not in seen, 'duplicate publication source')
        seen.add(pair)


def request_key(args, suffix=''):
    key = getattr(args, 'request_key', None)
    if not key and sys.stdin.isatty():
        key = input('稳定操作标识（结果不明时保留，禁止随意换键重试）: ').strip()
        args.request_key = key
    ident(key)
    return ident(key + suffix)


def confirm(args, flag, word, notice):
    print(notice, file=sys.stderr)
    if getattr(args, flag, False):
        return
    require(sys.stdin.isatty(), '--' + flag.replace('_', '-') + ' requires explicit operator consent')
    require(input('输入“' + word + '”确认，回车取消: ').strip() == word, 'canceled; no mutation requested')


def expected(args, current):
    value = getattr(args, 'revision', None)
    if value is None:
        require(sys.stdin.isatty(), 'explicit --revision required; inspect metadata before mutation')
        value = current
    counter(value)
    require(value == current, 'revision changed; inspect current metadata and confirm again (no automatic rebase)')
    return value


def active(api):
    value = api.request('GET', PREFIX + '/config')
    require(isinstance(value, dict) and 'revision' in value and 'config' in value, 'active config unavailable')
    counter(value['revision'])
    return value


def create_uuid(api, revision, key):
    require({'kind': 'uuid'} in inventory(api)['supportedKinds'], 'backend UUID generation unavailable; no fallback')
    return credential(api.command(PREFIX + '/credentials', 'credential_create', key, revision,
                                 {'kind': {'kind': 'uuid'}, 'confirmGenerate': True}))


def credential_picker(api, revision, key, protocol):
    """Returned callback is used only at credentialRef fields in the schema form."""
    def choose(path):
        require(protocol in ('vmess', 'vless'),
                'current managed wizard supports UUID protocols only; other credential kinds are not silently replaced')
        data = inventory(api)
        available = [c for c in data['credentials'] if c['state'] == 'available' and c['kind'] == {'kind': 'uuid'}]
        for index, item in enumerate(available, 1):
            print(f"{index}. {item['id']} (UUID，可用；不代表已应用)")
        can_generate = {'kind': 'uuid'} in data['supportedKinds']
        print('输入现有凭据编号' + ('，或“生成”显式创建一个新 UUID' if can_generate else '；后端生成器不可用'))
        answer = input('凭据选择（回车取消）: ').strip()
        if answer == '生成':
            require(can_generate, 'backend UUID generator unavailable')
            derived = ident(key + '-cred-' + digest(path.encode())[:12])
            print('凭据请求键: ' + derived + '；生成后仍须完成草稿/计划/应用。')
            item = create_uuid(api, revision, derived)
            print('已保存到加密凭据库；未应用，不代表隧道可用。')
            return item['secretRef']
        require(answer.isdigit() and 1 <= int(answer) <= len(available), 'canceled/invalid credential choice')
        return available[int(answer) - 1]['secretRef']
    return choose


def get_publication(api, args):
    identifier = getattr(args, 'publication_id', None)
    if not identifier and sys.stdin.isatty():
        identifier = input('订阅发布 ID: ').strip()
    ident(identifier)
    return publication(api.request('GET', PREFIX + '/publications/' + identifier))


def publication_wizard(api, args, current_active, previous=None):
    require(sys.stdin.isatty(), '--request-file with exact shared publication payload required')
    schema_path = Path(args.schema) if args.schema else Path(__file__).resolve().parents[2] / 'contracts/schema/v1.schema.json'
    form = SchemaForm(strict_json(read_regular(schema_path, 2 * 1024 * 1024)))
    listeners = ((current_active.get('config') or {}).get('listeners') or [])
    choices = [(listener, user) for listener in listeners if listener.get('enabled') is True
               and listener.get('protocol', {}).get('kind') == 'proxy'
               for user in listener['protocol'].get('users', []) if user.get('enabled') is True]
    require(choices, 'no enabled committed listener/user mapping; apply a verified configuration first')
    name = input('订阅名称' + ('（回车保留）' if previous else '') + ': ').strip()
    if previous and not name:
        name = previous['name']
    enabled_raw = input('启用发布？[是/否]: ').strip()
    require(enabled_raw in ('是', '否'), 'enabled must be explicit')
    for i, (listener, user) in enumerate(choices, 1):
        print(f"{i}. {ident(listener['id'])} / {ident(user['id'])}")
    raw = input('选择 listener/user 编号，多个以逗号分隔: ').strip().split(',')
    require(1 <= len(raw) <= 32 and all(v.strip().isdigit() and 1 <= int(v) <= len(choices) for v in raw), 'invalid source selection')
    require(len(set(int(v) for v in raw)) == len(raw), 'duplicate source choice')
    sources = []
    print('必须明确输入客户端连接地址；不会从 bind、Host 或管理地址猜测。loopback 仅开发测试，不可宣称手机可达。')
    for value in raw:
        listener, user = choices[int(value) - 1]
        endpoint = form.collect({'$ref': '#/$defs/Endpoint'}, 'publication.endpoint')
        # Never derive public TLS/REALITY material from a server private-key ref.
        security = form.collect({'$ref': '#/$defs/ClientSecurity'}, 'publication.clientSecurity')
        sources.append({'listenerId': listener['id'], 'userId': user['id'], 'endpoint': endpoint, 'clientSecurity': security})
    result = {'name': name, 'enabled': enabled_raw == '是', 'format': 'uri_list', 'sources': sources,
              'confirmPublishConnectionSecrets': True}
    if previous:
        result['sourceRevision'] = current_active['revision']
    return result


def payload_for_publication(api, args, current_active, previous=None):
    if args.request_file:
        payload = strict_json(read_regular(args.request_file, 256 * 1024))
    else:
        payload = publication_wizard(api, args, current_active, previous)
    fields = ('name', 'enabled', 'format', 'sources', 'confirmPublishConnectionSecrets')
    keys(payload, fields + (('sourceRevision',) if previous else ()))
    publication_fields(payload)
    require(payload['confirmPublishConnectionSecrets'] is True, 'confirmPublishConnectionSecrets must be true')
    if previous:
        require(payload['sourceRevision'] == current_active['revision'], 'sourceRevision must match current active config; no automatic rebase')
    return payload


def show_publication(value):
    emit(publication(value))
    print('sourceRevision 固定绑定已提交配置；配置改变后须明确 republish。到期时间为 Unix 毫秒，以服务器 token.state 为准。', file=sys.stderr)


def issue(api, args, current):
    require(sys.stdout.isatty(), 'one-time URL requires an actual terminal stdout; pipes/files/JSON receipts are refused before issuance')
    require(not args.json and not args.output and not args.request_file and not args.dry_run,
            'one-time URL cannot be saved to output, ordinary JSON, a request file or a plan')
    revision = expected(args, current['revision'])
    if args.action == 'publication-issue':
        require(current['token']['state'] == 'not_issued', 'token already existed; inspect metadata then deliberately use publication-rotate')
    else:
        require(current['token']['version'] > 0, 'no previous token; use publication-issue')
    expires = args.expires_in_seconds
    if expires is None and sys.stdin.isatty():
        raw = input('链接有效秒数（300..2592000；轮换同时更改到期时间）: ').strip()
        require(raw.isdigit(), 'explicit expiry required')
        expires = int(raw)
    require(type(expires) is int and 300 <= expires <= 2592000, '--expires-in-seconds must be 300..2592000')
    key = request_key(args)
    print(f"publication {current['id']} / revision {revision} / token version {current['token']['version']} / expiry +{expires}s", file=sys.stderr)
    confirm(args, 'show_secret_url', '显示链接', '只在本终端显示一次敏感 URL；请勿录屏/记录终端会话。轮换会使旧订阅链接失效。' + REVOCATION_NOTICE)
    result = None
    try:
        result = api.command(PREFIX + '/publications/' + current['id'] + '/token', 'publication_token_issue',
                             key, revision, {'expiresInSeconds': expires, 'confirmIssueSecretUrl': True},
                             etag=True, sensitive=True)
        keys(result, ('publication', 'subscriptionUrl', 'displayOnce'))
        require(result['displayOnce'] is True, 'unsupported sensitive response')
        value = publication(result['publication'])
        require(value['id'] == current['id'] and value['token']['state'] == 'active', 'unexpected issuance metadata')
        url = result.pop('subscriptionUrl')
        require(isinstance(url, str) and 1 <= len(url) <= 8192 and all(32 < ord(c) < 127 for c in url), 'invalid sensitive URL')
        parsed = urlsplit(url)
        require(parsed.scheme in ('https', 'http') and parsed.hostname and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment and
                re.fullmatch('/subscriptions/v1/' + re.escape(current['id']) + '/[A-Za-z0-9_-]+', parsed.path),
                'invalid sensitive URL shape')
        require(parsed.scheme == 'https' or parsed.hostname in ('127.0.0.1', 'localhost', '::1'), 'insecure non-loopback URL refused')
        if parsed.scheme == 'http':
            print('此 HTTP loopback 链接仅用于服务器本机开发测试，不是手机可访问的订阅。', file=sys.stderr)
        # Check the terminal again after the request; never fall back to a file.
        require(sys.stdout.isatty(), 'terminal changed; URL display refused')
        sys.stdout.write(url + '\n')
        sys.stdout.flush()
        url = None
        print('一次性 URL 已显示；后续只能查看元数据。', file=sys.stderr)
        show_publication(value)
        return 0
    except (InstallError, OSError, ValueError, TypeError, KeyError, KeyboardInterrupt):
        print(UNKNOWN_NOTICE, file=sys.stderr)
        try:
            show_publication(publication(api.request('GET', PREFIX + '/publications/' + current['id'])))
        except (InstallError, OSError, ValueError, TypeError, KeyError, KeyboardInterrupt):
            print('安全元数据暂不可用；保留原请求键，稍后运行 publication 查询。', file=sys.stderr)
        return 3
    finally:
        if isinstance(result, dict):
            result.clear()


def run(api, args):
    action = args.action
    if action == 'manage-subscriptions':
        return menu(api, args)
    require(not args.dry_run, 'these metadata actions have no plan/dry-run endpoint; no mutation requested')
    require(not args.output, 'publication/credential metadata actions never write files')
    if action == 'credentials':
        emit(inventory(api)); return 0
    if action == 'credential-create':
        revision = expected(args, active(api)['revision'])
        key = request_key(args)
        confirm(args, 'confirm_generate', '生成', '创建新 UUID 加密凭据记录；不等于节点已应用或已轮换。')
        emit(create_uuid(api, revision, key)); return 0
    if action == 'credential-retire':
        identifier = args.credential_id
        if not identifier and sys.stdin.isatty():
            identifier = input('待退役凭据 ID（不是 secretRef）: ').strip()
        ident(identifier)
        item = next((v for v in inventory(api)['credentials'] if v['id'] == identifier), None)
        require(item is not None, 'credential record not found')
        revision = expected(args, item['revision']); key = request_key(args)
        confirm(args, 'confirm_retire', '退役', '仅退役未被配置、草稿、计划或恢复历史引用的凭据；不是撤销节点访问。共享后端会拒绝仍被引用的记录。')
        emit(credential(api.command(PREFIX + '/credentials/' + identifier + '/retire', 'credential_retire', key,
                                    revision, {'confirmRetire': True}, etag=True)))
        return 0
    if action == 'publications':
        values = api.request('GET', PREFIX + '/publications')
        require(isinstance(values, list) and len(values) <= 16, 'invalid publication collection')
        emit([publication(value) for value in values]); return 0
    if action == 'publication-create':
        current_active = active(api)
        revision = expected(args, current_active['revision'])
        payload = payload_for_publication(api, args, current_active)
        key = request_key(args)
        emit({'activeRevision': revision, 'publication': payload})
        confirm(args, 'confirm_publish_connection_secrets', '发布', '发布将允许持有订阅链接的人获得所选用户的连接凭据；创建不自动签发链接。')
        show_publication(api.command(PREFIX + '/publications', 'publication_create', key, revision, payload))
        return 0
    current = get_publication(api, args)
    if action == 'publication':
        show_publication(current); print(REVOCATION_NOTICE, file=sys.stderr); return 0
    if action in ('publication-issue', 'publication-rotate'):
        return issue(api, args, current)
    revision = expected(args, current['revision']); key = request_key(args)
    if action == 'publication-revoke':
        confirm(args, 'confirm_revoke_access', '撤销链接', REVOCATION_NOTICE)
        show_publication(api.command(PREFIX + '/publications/' + current['id'] + '/token', 'publication_token_revoke',
                                      key, revision, {'confirmRevokeAccess': True}, verb='DELETE', etag=True))
        return 0
    require(action in ('publication-update', 'publication-republish'), 'unsupported action')
    current_active = active(api)
    if action == 'publication-republish':
        require(not args.request_file, 'republish preserves all sources; use publication-update for a full explicit replacement')
        source_revision = args.source_revision
        if source_revision is None:
            require(sys.stdin.isatty(), 'republish requires explicit --source-revision')
            source_revision = current_active['revision']
        require(counter(source_revision, 1) == current_active['revision'], 'source revision changed; no automatic rebase')
        payload = {key: copy.deepcopy(current[key]) for key in ('name', 'enabled', 'format', 'sources')}
        payload.update(sourceRevision=source_revision, confirmPublishConnectionSecrets=True)
    else:
        payload = payload_for_publication(api, args, current_active, current)
    emit({'publicationId': current['id'], 'expectedRevision': revision, 'replacement': payload})
    confirm(args, 'confirm_publish_connection_secrets', '重新发布',
            '全量替换发布并固定到所示 active revision；无静默字段丢弃。禁用会撤销链接，重新启用后需显式签发。')
    show_publication(api.command(PREFIX + '/publications/' + current['id'], 'publication_replace', key,
                                revision, payload, verb='PUT', etag=True))
    return 0


def menu(api, args):
    require(sys.stdin.isatty(), 'subscription menu requires interactive stdin')
    choices = [('查看发布与到期状态', 'publications'), ('创建发布', 'publication-create'),
               ('查看一个发布', 'publication'), ('完整更新发布', 'publication-update'),
               ('重新绑定已提交版本', 'publication-republish'), ('签发一次性链接', 'publication-issue'),
               ('轮换链接/更改到期时间', 'publication-rotate'), ('撤销订阅链接', 'publication-revoke'),
               ('查看连接凭据', 'credentials'), ('显式生成 UUID 凭据', 'credential-create'),
               ('退役未使用凭据', 'credential-retire')]
    print('订阅管理：UUID 生成能力不代表协议认证；loopback 不是手机可达地址。')
    print(REVOCATION_NOTICE)
    for index, (label, _) in enumerate(choices, 1):
        print(f'{index}. {label}')
    raw = input('选择编号（回车取消）: ').strip()
    if not raw:
        return 0
    require(raw.isdigit() and 1 <= int(raw) <= len(choices), 'invalid menu choice')
    args.action = choices[int(raw) - 1][1]
    # Single deliberate action per invocation: no hidden loop or repeated issue.
    return run(api, args)

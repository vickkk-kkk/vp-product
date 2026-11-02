import 'package:vp_contracts/vp_contracts.dart';
import 'wire.dart' as wire;

void keys(Map<String, Object?> value, Set<String> required) {
  if (value.keys.toSet().difference(required).isNotEmpty ||
      required.difference(value.keys.toSet()).isNotEmpty)
    throw wire.malformed;
}

int positive(Object? value) {
  final n = wire.revision(value);
  if (n < 1) throw wire.malformed;
  return n;
}

DateTime date(Object? value) =>
    DateTime.fromMillisecondsSinceEpoch(wire.timestamp(value), isUtc: true);
DateTime? optionalDate(Object? value) => value == null ? null : date(value);
String secretRef(Object? value) {
  final s = wire.string(value, max: 135);
  if (!RegExp(r'^secret:[A-Za-z0-9_-]{1,128}$').hasMatch(s))
    throw wire.malformed;
  return s;
}

String label(Object? value) {
  final result = wire.string(value, max: 256);
  if (result.runes.length > 128 ||
      result.trim().isEmpty ||
      result.contains(RegExp(r'[\x00-\x1f\x7f]')))
    throw wire.malformed;
  return result;
}

String numericBind(String value) {
  final parts = value.split('.');
  if (parts.length == 4 &&
      parts.every(
        (s) =>
            RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(s) && int.parse(s) <= 255,
      ))
    return value;
  if (value.contains(':') &&
      !value.contains('%') &&
      !value.contains('[') &&
      !value.contains(']')) {
    final uri = Uri.tryParse('http://[$value]');
    if (uri != null && uri.host == value.toLowerCase()) return value;
  }
  throw const ProductFailure(
    'CONFIG_INVALID',
    '监听地址必须是明确的数字 IP 地址。',
    definitelyNotApplied: true,
  );
}

String host(Object? value) {
  final result = wire.string(value, max: 253);
  if (result.trim() != result ||
      result.contains(RegExp(r'[\s/@?#]')) ||
      result.contains('://'))
    throw wire.malformed;
  return result;
}

CredentialKind credentialKind(Object? value) {
  final item = wire.object(value);
  final kind = wire.code(item['kind']);
  if (kind == 'shadowsocks') {
    keys(item, {'kind', 'method'});
    final method = wire.string(item['method']);
    if (!const {
      'aes-128-gcm',
      'aes-256-gcm',
      'chacha20-ietf-poly1305',
      '2022-blake3-aes-128-gcm',
      '2022-blake3-aes-256-gcm',
      '2022-blake3-chacha20-poly1305',
      'xchacha20-ietf-poly1305',
    }.contains(method))
      throw wire.malformed;
    return CredentialKind(kind, method: method);
  }
  keys(item, {'kind'});
  if (!const {
    'uuid',
    'password',
    'username_password',
    'uuid_password',
  }.contains(kind))
    throw wire.malformed;
  return CredentialKind(kind);
}

ManagedCredential credential(Object? value) {
  final item = wire.object(value);
  keys(item, {
    'schemaVersion',
    'id',
    'revision',
    'kind',
    'secretRef',
    'state',
    'createdAt',
    'displayKey',
  });
  wire.schema(item);
  final state = switch (item['state']) {
    'available' => ManagedCredentialState.available,
    'retired' => ManagedCredentialState.retired,
    _ => throw wire.malformed,
  };
  final displayKey = wire.code(item['displayKey']);
  if (displayKey !=
      (state == ManagedCredentialState.available
          ? 'credential.managed'
          : 'credential.retired'))
    throw wire.malformed;
  return ManagedCredential(
    id: wire.id(item['id']),
    revision: positive(item['revision']),
    kind: credentialKind(item['kind']),
    secretRef: secretRef(item['secretRef']),
    state: state,
    createdAt: date(item['createdAt']),
    displayKey: displayKey,
  );
}

CredentialInventoryView inventory(Object? value) {
  final item = wire.object(value);
  keys(item, {'schemaVersion', 'credentials', 'supportedKinds'});
  wire.schema(item);
  final credentials = wire.array(item['credentials']).map(credential).toList();
  final kinds = wire.array(item['supportedKinds']).map(credentialKind).toList();
  if (credentials.length > 128 ||
      kinds.length > 11 ||
      kinds.toSet().length != kinds.length ||
      credentials.map((c) => c.id).toSet().length != credentials.length)
    throw wire.malformed;
  return CredentialInventoryView(
    supportedKinds: kinds,
    credentials: credentials,
  );
}

PublicationTlsTrust trust(Object? value) {
  final item = wire.object(value);
  switch (item['kind']) {
    case 'system':
      keys(item, {'kind'});
      return const PublicationSystemTrust();
    case 'custom_ca':
      keys(item, {'kind', 'certificateRef'});
      return PublicationCustomCaTrust(wire.id(item['certificateRef']));
    case 'spki_sha256':
      keys(item, {'kind', 'pins'});
      final pins = wire.array(item['pins']).map(wire.hash).toList();
      if (pins.isEmpty) throw wire.malformed;
      return PublicationSpkiTrust(pins);
    default:
      throw wire.malformed;
  }
}

String? fingerprint(Object? value) {
  if (value == null) return null;
  final f = wire.string(value, max: 64);
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(f)) throw wire.malformed;
  return f;
}

PublicationSecurity security(Object? value) {
  final item = wire.object(value);
  switch (item['kind']) {
    case 'none':
      keys(item, {'kind'});
      return const PublicationSecurityNone();
    case 'tls':
      keys(item, {
        'kind',
        'serverName',
        'alpn',
        'trust',
        'clientHelloFingerprint',
      });
      return PublicationSecurityTls(
        serverName: host(item['serverName']),
        alpn: wire
            .array(item['alpn'])
            .map((x) => wire.string(x, max: 255))
            .toList(),
        trust: trust(item['trust']),
        clientHelloFingerprint: fingerprint(item['clientHelloFingerprint']),
      );
    case 'reality':
      keys(item, {
        'kind',
        'serverName',
        'publicKey',
        'shortId',
        'clientHelloFingerprint',
      });
      final key = wire.string(item['publicKey'], max: 43);
      final short = item['shortId'];
      if (!RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(key) ||
          short is! String ||
          !RegExp(r'^(?:[0-9A-Fa-f]{2}){0,8}$').hasMatch(short))
        throw wire.malformed;
      return PublicationSecurityReality(
        serverName: host(item['serverName']),
        publicKey: key,
        shortId: short,
        clientHelloFingerprint: fingerprint(item['clientHelloFingerprint']),
      );
    default:
      throw wire.malformed;
  }
}

Map<String, Object?> encodeTrust(PublicationTlsTrust value) => switch (value) {
  PublicationSystemTrust() => {'kind': 'system'},
  PublicationCustomCaTrust(:final certificateRef) => {
    'kind': 'custom_ca',
    'certificateRef': wire.id(certificateRef),
  },
  PublicationSpkiTrust(:final pins) => {
    'kind': 'spki_sha256',
    'pins': pins.map(wire.hash).toList(),
  },
};
Map<String, Object?> encodeSecurity(PublicationSecurity value) {
  final Map<String, Object?> out = switch (value) {
    PublicationSecurityNone() => {'kind': 'none'},
    PublicationSecurityTls(
      :final serverName,
      :final alpn,
      :final trust,
      :final clientHelloFingerprint,
    ) =>
      {
        'kind': 'tls',
        'serverName': serverName,
        'alpn': alpn,
        'trust': encodeTrust(trust),
        'clientHelloFingerprint': clientHelloFingerprint,
      },
    PublicationSecurityReality(
      :final serverName,
      :final publicKey,
      :final shortId,
      :final clientHelloFingerprint,
    ) =>
      {
        'kind': 'reality',
        'serverName': serverName,
        'publicKey': publicKey,
        'shortId': shortId,
        'clientHelloFingerprint': clientHelloFingerprint,
      },
  };
  security(out);
  return out;
}

PublicationSourceMapping source(Object? value) {
  final item = wire.object(value);
  keys(item, {'listenerId', 'userId', 'endpoint', 'clientSecurity'});
  final endpoint = wire.object(item['endpoint']);
  keys(endpoint, {'host', 'port'});
  return PublicationSourceMapping(
    listenerId: wire.id(item['listenerId']),
    userId: wire.id(item['userId']),
    host: host(endpoint['host']),
    port: wire.port(endpoint['port']),
    security: security(item['clientSecurity']),
  );
}

Map<String, Object?> encodeSource(PublicationSourceMapping value) => {
  'listenerId': wire.id(value.listenerId),
  'userId': wire.id(value.userId),
  'endpoint': {'host': host(value.host), 'port': wire.port(value.port)},
  'clientSecurity': encodeSecurity(value.security),
};
PublishedSubscription publication(Object? value) {
  final item = wire.object(value);
  keys(item, {
    'schemaVersion',
    'id',
    'name',
    'revision',
    'sourceRevision',
    'enabled',
    'format',
    'sources',
    'token',
    'createdAt',
    'updatedAt',
    'lastSuccessfulReadAt',
  });
  wire.schema(item);
  if (item['format'] != 'uri_list') throw wire.malformed;
  final sources = wire.array(item['sources']).map(source).toList();
  if (sources.isEmpty ||
      sources.length > 32 ||
      sources.map((s) => '${s.listenerId}/${s.userId}').toSet().length !=
          sources.length)
    throw wire.malformed;
  final token = wire.object(item['token']);
  keys(token, {'state', 'version', 'issuedAt', 'expiresAt'});
  final state = switch (token['state']) {
    'not_issued' => PublicationTokenState.notIssued,
    'active' => PublicationTokenState.active,
    'revoked' => PublicationTokenState.revoked,
    'expired' => PublicationTokenState.expired,
    _ => throw wire.malformed,
  };
  final version = wire.revision(token['version']);
  final issuedAt = optionalDate(token['issuedAt']);
  final expiresAt = optionalDate(token['expiresAt']);
  if (state == PublicationTokenState.notIssued &&
      (version != 0 || issuedAt != null || expiresAt != null))
    throw wire.malformed;
  if ((state == PublicationTokenState.active ||
          state == PublicationTokenState.expired ||
          state == PublicationTokenState.revoked) &&
      (version == 0 ||
          issuedAt == null ||
          expiresAt == null ||
          !expiresAt.isAfter(issuedAt)))
    throw wire.malformed;
  if (date(item['createdAt']).isAfter(date(item['updatedAt'])) ||
      (!wire.boolean(item['enabled']) && state == PublicationTokenState.active))
    throw wire.malformed;
  return PublishedSubscription(
    id: wire.id(item['id']),
    name: label(item['name']),
    revision: positive(item['revision']),
    sourceRevision: positive(item['sourceRevision']),
    enabled: wire.boolean(item['enabled']),
    sources: sources,
    token: PublicationTokenMetadata(
      state: state,
      version: version,
      issuedAt: issuedAt,
      expiresAt: expiresAt,
    ),
    createdAt: date(item['createdAt']),
    updatedAt: date(item['updatedAt']),
    lastSuccessfulReadAt: optionalDate(item['lastSuccessfulReadAt']),
  );
}

List<PublishedSubscription> publications(Object? value) {
  final result = wire.array(value).map(publication).toList();
  if (result.length > 16 ||
      result.map((p) => p.id).toSet().length != result.length)
    throw wire.malformed;
  return List.unmodifiable(result);
}

Map<String, Object?> draft(PublicationDraft value) {
  try {
    if (value.sources.isEmpty ||
        value.sources.length > 32 ||
        value.sources
                .map((s) => '${s.listenerId}/${s.userId}')
                .toSet()
                .length !=
            value.sources.length)
      throw wire.malformed;
    return {
      'name': label(value.name),
      'enabled': value.enabled,
      'format': 'uri_list',
      'sources': value.sources.map(encodeSource).toList(),
      'confirmPublishConnectionSecrets': true,
    };
  } catch (_) {
    // Pure local encoding has made no HTTP request, so rejection is known.
    throw const ProductFailure(
      'CONFIG_INVALID',
      '请检查订阅名称、来源、连接地址与安全映射。',
      definitelyNotApplied: true,
    );
  }
}

OneTimePublicationSecret issued(
  Object? value,
  String id,
  int epoch,
  Uri managementOrigin,
) {
  final item = wire.object(value);
  keys(item, {'publication', 'subscriptionUrl', 'displayOnce'});
  final summary = publication(item['publication']);
  if (summary.id != id ||
      !summary.enabled ||
      summary.token.state != PublicationTokenState.active ||
      item['displayOnce'] != true)
    throw wire.malformed;
  final raw = wire.string(item['subscriptionUrl'], max: 8192);
  final url = Uri.tryParse(raw);
  if (url == null ||
      !url.hasAuthority ||
      url.userInfo.isNotEmpty ||
      url.hasQuery ||
      url.hasFragment ||
      url.host.isEmpty ||
      !RegExp(
        '^/subscriptions/v1/${RegExp.escape(id)}/vps1_[0-9a-f]{64}\$',
      ).hasMatch(url.path) ||
      url.port < 1 ||
      url.port > 65535)
    throw wire.malformed;
  final loopback =
      url.scheme == 'http' &&
      const {'localhost', '127.0.0.1', '::1'}.contains(url.host);
  if (url.scheme != 'https' && !loopback) throw wire.malformed;
  if (loopback && url.origin != managementOrigin.origin) throw wire.malformed;
  return OneTimePublicationSecret(
    publication: summary,
    subscriptionUrl: raw,
    sessionEpoch: epoch,
    developmentLoopback: loopback,
  );
}

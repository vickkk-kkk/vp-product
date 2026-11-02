import '../vp_contracts.dart' show ChangePlan, MutationIdentity, PresetView;

/// Safe metadata only. A generator kind is not protocol certification.
class CredentialKind {
  const CredentialKind(this.kind, {this.method});
  final String kind;
  final String? method;
  bool get isUuid => kind == 'uuid' && method == null;
  @override
  bool operator ==(Object other) =>
      other is CredentialKind && other.kind == kind && other.method == method;
  @override
  int get hashCode => Object.hash(kind, method);
  @override
  String toString() => method == null ? kind : '$kind/$method';
}

enum ManagedCredentialState { available, retired }

class ManagedCredential {
  const ManagedCredential({
    required this.id,
    required this.revision,
    required this.kind,
    required this.secretRef,
    required this.state,
    required this.createdAt,
    required this.displayKey,
  });
  final String id, secretRef, displayKey;
  final int revision;
  final CredentialKind kind;
  final ManagedCredentialState state;
  final DateTime createdAt;
}

class CredentialInventoryView {
  CredentialInventoryView({
    required List<CredentialKind> supportedKinds,
    required List<ManagedCredential> credentials,
  }) : supportedKinds = List.unmodifiable(supportedKinds),
       credentials = List.unmodifiable(credentials);
  final List<CredentialKind> supportedKinds;
  final List<ManagedCredential> credentials;
  bool get supportsUuid => supportedKinds.any((kind) => kind.isUuid);
}

/// Explicit client-facing trust settings. No skip-verification variant exists.
sealed class PublicationSecurity {
  const PublicationSecurity();
  String get kind;
}

class PublicationSecurityNone extends PublicationSecurity {
  const PublicationSecurityNone();
  @override
  String get kind => 'none';
}

class PublicationSecurityTls extends PublicationSecurity {
  PublicationSecurityTls({
    required this.serverName,
    required List<String> alpn,
    required this.trust,
    this.clientHelloFingerprint,
  }) : alpn = List.unmodifiable(alpn);
  final String serverName;
  final List<String> alpn;
  final PublicationTlsTrust trust;
  final String? clientHelloFingerprint;
  @override
  String get kind => 'tls';
}

class PublicationSecurityReality extends PublicationSecurity {
  const PublicationSecurityReality({
    required this.serverName,
    required this.publicKey,
    required this.shortId,
    this.clientHelloFingerprint,
  });
  final String serverName, publicKey, shortId;
  final String? clientHelloFingerprint;
  @override
  String get kind => 'reality';
}

sealed class PublicationTlsTrust {
  const PublicationTlsTrust();
}

class PublicationSystemTrust extends PublicationTlsTrust {
  const PublicationSystemTrust();
}

class PublicationCustomCaTrust extends PublicationTlsTrust {
  const PublicationCustomCaTrust(this.certificateRef);
  final String certificateRef;
}

class PublicationSpkiTrust extends PublicationTlsTrust {
  PublicationSpkiTrust(List<String> pins) : pins = List.unmodifiable(pins);
  final List<String> pins;
}

class PublicationSourceMapping {
  const PublicationSourceMapping({
    required this.listenerId,
    required this.userId,
    required this.host,
    required this.port,
    required this.security,
  });
  final String listenerId, userId, host;
  final int port;
  final PublicationSecurity security;
}

class PublicationSourceCandidate {
  const PublicationSourceCandidate({
    required this.listenerId,
    required this.listenerName,
    required this.userId,
    required this.protocol,
    required this.transport,
    required this.securityKind,
    required this.bindAddress,
    required this.bindPort,
    required this.selectable,
    required this.reason,
  });
  final String listenerId,
      listenerName,
      userId,
      protocol,
      transport,
      securityKind,
      bindAddress;
  final int bindPort;
  final bool selectable;
  final String reason;
  // No endpoint is inferred from bind address; callers must map it explicitly.
}

enum PublicationTokenState { notIssued, active, revoked, expired }

class PublicationTokenMetadata {
  const PublicationTokenMetadata({
    required this.state,
    required this.version,
    this.issuedAt,
    this.expiresAt,
  });
  final PublicationTokenState state;
  final int version;
  final DateTime? issuedAt, expiresAt;
}

class PublishedSubscription {
  PublishedSubscription({
    required this.id,
    required this.name,
    required this.revision,
    required this.sourceRevision,
    required this.enabled,
    required List<PublicationSourceMapping> sources,
    required this.token,
    required this.createdAt,
    required this.updatedAt,
    this.lastSuccessfulReadAt,
  }) : sources = List.unmodifiable(sources);
  final String id, name;
  final int revision, sourceRevision;
  final bool enabled;
  final List<PublicationSourceMapping> sources;
  final PublicationTokenMetadata token;
  final DateTime createdAt, updatedAt;
  final DateTime? lastSuccessfulReadAt;
}

class PublicationDraft {
  PublicationDraft({
    required this.name,
    required this.enabled,
    required List<PublicationSourceMapping> sources,
  }) : sources = List.unmodifiable(sources);
  final String name;
  final bool enabled;
  final List<PublicationSourceMapping> sources;
}

class PublicationWorkspace {
  PublicationWorkspace({
    required this.activeRevision,
    required this.observedRevision,
    required List<ManagedCredential> credentials,
    required List<CredentialKind> supportedKinds,
    required List<PublicationSourceCandidate> sources,
    required List<PublishedSubscription> publications,
    this.developmentBuild,
    List<PresetView> presets = const [],
  }) : presets = List.unmodifiable(presets),
       credentials = List.unmodifiable(credentials),
       supportedKinds = List.unmodifiable(supportedKinds),
       sources = List.unmodifiable(sources),
       publications = List.unmodifiable(publications);
  final int activeRevision;
  final int? observedRevision;
  final List<ManagedCredential> credentials;
  final List<CredentialKind> supportedKinds;
  final List<PublicationSourceCandidate> sources;
  final List<PublishedSubscription> publications;
  final bool? developmentBuild;
  final List<PresetView> presets;
  bool get supportsUuid => supportedKinds.any((kind) => kind.isUuid);
}

class NewUuidListenerInput {
  const NewUuidListenerInput({
    required this.listenerId,
    required this.userId,
    required this.name,
    required this.bindAddress,
    required this.port,
  });
  final String listenerId, userId, name, bindAddress;
  final int port;
}

/// Dedicated ephemeral handoff, never a normal view state or serializable DTO.
/// Taking/disposing drops this object's reference; Dart strings cannot promise
/// process-memory erasure. The display owner must also clear on focus/session loss.
class OneTimePublicationSecret {
  OneTimePublicationSecret({
    required this.publication,
    required String subscriptionUrl,
    required this.sessionEpoch,
    required this.developmentLoopback,
  }) : _url = subscriptionUrl;
  final PublishedSubscription publication;
  final int sessionEpoch;
  final bool developmentLoopback;
  String? _url;
  bool get isAvailable => _url != null;
  String? takeOnce() {
    final value = _url;
    _url = null;
    return value;
  }

  void dispose() {
    _url = null;
  }

  @override
  String toString() => 'OneTimePublicationSecret([REDACTED])';
}

abstract interface class PublicationManagementApi {
  Future<PublicationWorkspace> readPublicationWorkspace();
  Future<CredentialInventoryView> credentialInventory();
  Future<ManagedCredential> generateUuidCredential(MutationIdentity command);
  Future<ManagedCredential> retireCredential(
    String id,
    MutationIdentity command,
  );
  Future<List<PublishedSubscription>> publications();
  Future<PublishedSubscription> getPublication(String id);
  Future<PublishedSubscription> createPublication(
    PublicationDraft draft,
    MutationIdentity command,
  );
  Future<PublishedSubscription> replacePublication(
    String id,
    PublicationDraft draft,
    int sourceRevision,
    MutationIdentity command,
  );
  Future<OneTimePublicationSecret> issuePublicationToken(
    String id,
    int expiresInSeconds,
    MutationIdentity command,
  );
  Future<PublishedSubscription> revokePublicationToken(
    String id,
    MutationIdentity command,
  );
  Future<ChangePlan> prepareNewUuidListener(
    NewUuidListenerInput input,
    ManagedCredential credential,
    MutationIdentity command,
  );
}

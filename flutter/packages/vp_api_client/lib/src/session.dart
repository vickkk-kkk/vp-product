/// Management authentication is separate from node credentials and native runtime.
abstract interface class ManagementSession {
  bool get canAuthenticate;
  bool get authenticated;
  String get originLabel;
  Future<void> restoreSession();
  Future<void> login(String username, String password, {String? secondFactor});
  Future<void> logout();
  void close();
}

/// Optional synchronous invalidation boundary, without making existing session
/// mocks pretend to support it. Epoch changes never carry credentials or URLs.
abstract interface class ManagementSessionEpoch {
  int get sessionEpoch;
  void addSessionListener(void Function() listener);
  void removeSessionListener(void Function() listener);
}

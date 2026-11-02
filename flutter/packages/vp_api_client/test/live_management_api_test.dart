// Explicit opt-in loopback transport integration. This is NOT a browser test.
// Cookies/Origin below are test-only IO fixtures; Chromium semantics are untested.
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'package:vp_contracts/vp_contracts.dart';

const liveOrigin = String.fromEnvironment('VP_LIVE_MANAGEMENT_ORIGIN');

class LoopbackCookieFixture extends http.BaseClient {
  LoopbackCookieFixture(this.origin);
  final Uri origin;
  final http.Client inner = IOClient(HttpClient()..findProxy = (_) => 'DIRECT');
  String? cookie;
  int requests = 0;
  final trace = <String>[];
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (request.url.origin != origin.origin ||
        origin.host != 'localhost' ||
        origin.scheme != 'http') {
      throw StateError(
        'Live test is restricted to the explicit localhost origin.',
      );
    }
    requests++;
    if (request.method != 'GET') request.headers['Origin'] = origin.origin;
    if (cookie != null) request.headers['Cookie'] = cookie!;
    trace.add('${request.method} ${request.url.path}');
    final http.StreamedResponse response;
    try {
      response = await inner.send(request);
    } catch (error) {
      trace.add('transport exception type: ${error.runtimeType}');
      rethrow;
    }
    trace.add('HTTP ${response.statusCode}');
    final setCookie = response.headers['set-cookie'];
    if (setCookie != null) {
      final parsed = Cookie.fromSetCookieValue(setCookie);
      trace.add(
        'cookie flags: HttpOnly=${parsed.httpOnly}, Secure=${parsed.secure}, MaxAgeZero=${parsed.maxAge == 0}',
      );
      expect(parsed.name, 'vp_session');
      expect(parsed.httpOnly, isTrue);
      expect(parsed.secure, isTrue);
      cookie = parsed.maxAge == 0 ? null : '${parsed.name}=${parsed.value}';
    }
    return response;
  }

  @override
  void close() {
    cookie = null;
    inner.close();
  }
}

void main() {
  test(
    'actual loopback daemon auth, canonical snapshot projection and revocation',
    () async {
      final origin = Uri.parse(liveOrigin);
      final fixture = LoopbackCookieFixture(origin);
      final api = HttpManagementApi(client: fixture, origin: origin);
      addTearDown(api.close);
      addTearDown(() {
        for (final line in fixture.trace) {
          // ignore: avoid_print
          print(line);
        }
      });
      await expectLater(api.restoreSession(), throwsA(isA<ProductFailure>()));
      expect(api.authenticated, isFalse);
      await expectLater(
        api.login('synthetic-admin', 'deliberately-wrong-test-only'),
        throwsA(isA<ProductFailure>()),
      );
      expect(api.authenticated, isFalse);
      await api.login(
        'synthetic-admin',
        'synthetic-browser-qa-only-not-for-production-0123456789',
      );
      expect(api.authenticated, isTrue);
      expect(fixture.cookie, isNotNull);
      await api.restoreSession();
      final snapshot = await api.snapshot();
      expect(snapshot.hostLabel, 'localhost');
      expect(snapshot.revision, '0');
      expect(snapshot.observedRevision, isNull);
      expect(snapshot.listeners, isEmpty);
      expect(snapshot.operations, isEmpty);
      expect(snapshot.presets.length, 22);
      expect(
        snapshot.presets.every(
          (preset) => preset.capability.status != CapabilityStatus.certified,
        ),
        isTrue,
      );
      await api.logout();
      expect(api.authenticated, isFalse);
      expect(fixture.cookie, isNull);
      await expectLater(api.restoreSession(), throwsA(isA<ProductFailure>()));
      expect(api.authenticated, isFalse);
      expect(fixture.requests, greaterThanOrEqualTo(10));
    },
    skip: liveOrigin.isEmpty
        ? 'Requires explicit isolated daemon fixture; never uses deployment accounts.'
        : false,
  );
}

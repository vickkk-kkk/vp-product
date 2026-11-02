import 'dart:async';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:vp_contracts/vp_contracts.dart';
import 'package:vp_runtime_platform/vp_runtime_platform.dart';
import 'package:vp_api_client/vp_api_client.dart';
import 'controllers.dart';
import 'publication_controller.dart';

/// Composition roots replace ports only after platform/API adapter verification.
final runtimeProvider = Provider<RuntimeControl>(
  (ref) => const UnavailableRuntime(),
);
final repositoryProvider = Provider<ClientRepository>(
  (ref) => const UnavailableClientRepository(),
);
final importServiceProvider = Provider<ImportService>(
  (ref) => const UnavailableImportService(),
);
final managementApiProvider = Provider<ManagementApi>(
  (ref) => const UnavailableManagementApi(),
);
final diagnosticsProvider = Provider<DiagnosticsService>(
  (ref) => const UnavailableDiagnostics(),
);
final inventoryProvider = Provider<InventoryController>((ref) {
  final controller = InventoryController(ref.watch(repositoryProvider));
  ref.onDispose(controller.dispose);
  unawaited(controller.refresh());
  return controller;
});
final connectionProvider = Provider<ConnectionController>((ref) {
  final controller = ConnectionController(ref.watch(runtimeProvider));
  ref.onDispose(controller.dispose);
  unawaited(controller.refresh());
  return controller;
});
final adminProvider = Provider<AdminController>((ref) {
  final controller = AdminController(ref.watch(managementApiProvider));
  ref.onDispose(controller.dispose);
  unawaited(controller.refresh());
  return controller;
});
final importControllerProvider = Provider<ImportController>((ref) {
  final controller = ImportController(ref.watch(importServiceProvider));
  ref.onDispose(controller.dispose);
  return controller;
});

final managementSessionProvider = Provider<ManagementSession>((ref) {
  final api = ref.watch(managementApiProvider);
  return api is ManagementSession
      ? api as ManagementSession
      : const UnavailableManagementApi();
});

final publicationProvider = Provider<PublicationController>((ref) {
  final api = ref.watch(managementApiProvider);
  final admin = ref.watch(adminProvider);
  final controller = PublicationController(
    api is PublicationManagementApi
        ? api as PublicationManagementApi
        : const UnavailableManagementApi(),
    ref.watch(managementSessionProvider),
    otherMutationBlocked: () => admin.mutation.blocked,
  );
  admin.addListener(controller.changed);
  ref.onDispose(() => admin.removeListener(controller.changed));
  ref.onDispose(controller.dispose);
  unawaited(controller.refresh());
  return controller;
});

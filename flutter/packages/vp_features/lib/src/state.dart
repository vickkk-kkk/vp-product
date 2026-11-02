import 'package:vp_contracts/vp_contracts.dart';

sealed class LoadState<T> {
  const LoadState();
  T? get previous;
}

class Loading<T> extends LoadState<T> {
  const Loading([this.previous]);
  @override
  final T? previous;
}

class Loaded<T> extends LoadState<T> {
  const Loaded(this.value);
  final T value;
  @override
  T get previous => value;
}

class LoadFailed<T> extends LoadState<T> {
  const LoadFailed(this.error, [this.previous]);
  final ProductFailure error;
  @override
  final T? previous;
}

sealed class MutationState {
  const MutationState();
  bool get blocked => this is MutationRunning || this is MutationUncertain;
}

class MutationIdle extends MutationState {
  const MutationIdle();
}

class MutationRunning extends MutationState {
  const MutationRunning(this.label, this.identity);
  final String label;
  final MutationIdentity identity;
}

class MutationSucceeded extends MutationState {
  const MutationSucceeded(this.label, this.operationId);
  final String label, operationId;
}

class MutationFailed extends MutationState {
  const MutationFailed(this.error);
  final ProductFailure error;
}

class MutationUncertain extends MutationState {
  const MutationUncertain(this.error, this.identity);
  final ProductFailure error;
  final MutationIdentity identity;
}

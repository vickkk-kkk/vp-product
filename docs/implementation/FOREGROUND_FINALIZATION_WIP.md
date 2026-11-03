# Foreground journal finalization: work in progress

A user-supplied VPS report for `v0.1.0-lab.1` observed that the test worker and
listeners had exited after a clean signal, while the durable journal remained at
`candidate_started` with its historical active-process record. The report did
not establish external protocol forwarding or test automatic recovery.

The existing coordinator deferred terminal journal finalization until a future
operation. The foreground lab did not schedule that next operation, so a
successful committed session could retain that phase after exit. The development
candidate now requests finalization immediately after the control operation is
committed and before exporting client credentials. It accepts only an exactly
paired committed operation; uncommitted, inconsistent, previously finalized,
poisoned or uncertain states fail closed. Atomic publication still uses the
existing journal persistence barriers.

Finalization moves the journal to `idle` and retains the historical owned
process record. **That record is not a live-process claim or a durable shutdown
receipt.** A separate process-identity observation is required to establish that
the exact process is absent. A crash or signal before finalization can still
leave a nonterminal record, and uncertain I/O must be inspected rather than
blindly retried. Automatic restart and reopening are not implemented.

Synthetic pairing/guard tests and the runtime regression suite passed locally.
The new path has not yet been exercised after a successful live deployment or
on the VPS; it must be verified by an authorized tester before claiming that
this observation is resolved in an actual session. Do not modify the retained
VPS evidence without the user's explicit authorization.

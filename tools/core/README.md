# Pinned core reconstruction

The product depends on a generated `integration/vp_core` checkout. It is not
vendored and is intentionally absent from a fresh clone. `core-lock.json` pins
the upstream commit/tree, ordered patch SHA-256 hashes and resulting tree/commit.

Obtain a clean, separately checked-out copy of the repository named in
`core-lock.json`, at exactly its `upstream.commit`. Then, from the product root:

```sh
python tools/core/core_pipeline.py verify --upstream /absolute/path/to/vp_core
python tools/core/core_pipeline.py prepare --upstream /absolute/path/to/vp_core
python tools/core/core_pipeline.py check --upstream /absolute/path/to/vp_core
```

These commands do not compile, fetch dependencies or test runtime behavior.
They add deterministic Git objects/worktree registrations to the selected source
repository; use a dedicated clean checkout. Dirty or mismatched sources are
rejected, not overwritten. Do not point to an unrelated development checkout.

Only after successful preparation should Cargo commands be run. Even optional
path dependencies may require the checkout during workspace resolution. Keep the
committed Cargo.lock and rust-toolchain.toml; do not silently update pins.

Tooling-only synthetic Git tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tools/core -p 'test_*.py' -v
```

Passing those tests is not a replay of the real core or a product build result.

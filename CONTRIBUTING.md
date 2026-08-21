# Contributing

ComplyRoll is pre-alpha. Contributions should make the VDR evidence pipeline more correct,
traceable, or usable without weakening its domain invariants.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

Runtime dependency: `jsonschema[format-nongpl]` for Draft 2020-12 report validation (ADR 0006).
Everything else is the Python standard library. A new runtime dependency needs an ADR with a
security and maintenance assessment before it is added.

## Before opening a pull request

```bash
python3 -m compileall -q src tests stigroll.py
python3 -m unittest discover -s tests -v
```

Please include:

- Tests for new behavior.
- Synthetic examples without sensitive or customer data.
- An architecture decision record for significant design changes.
- The official FedRAMP rule or schema identifier when implementing policy behavior.

## Developer Certificate of Origin

Every commit must carry a `Signed-off-by: Your Name <you@example.com>` line (`git commit -s`)
certifying the [Developer Certificate of Origin](https://developercertificate.org/). This keeps
the provenance of contributions clear and keeps future licensing decisions possible.

## What must never enter the repository

Do not include credentials, real trust-center data, customer findings, private infrastructure
details, or exploit-enabling evidence. Real assessment artifacts (CKL, CKLB, XCCDF, ARF, scanner
exports) often carry Controlled Unclassified Information markings; never attach them to issues or
pull requests. Reproduce with the fixtures under `tests/fixtures/` or a redacted copy that keeps
only rule identifiers and statuses.

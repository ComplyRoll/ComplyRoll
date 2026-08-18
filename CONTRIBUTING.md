# Contributing

TrustRoll is pre-alpha. Contributions should make the VDR evidence pipeline more correct,
traceable, or usable without weakening its domain invariants.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

The package intentionally has no runtime dependencies in the initial scaffold.

## Before opening a pull request

```bash
python3 -m compileall -q src tests
python3 -m unittest discover -s tests -v
```

Please include:

- Tests for new behavior.
- Synthetic examples without sensitive or customer data.
- An architecture decision record for significant design changes.
- The official FedRAMP rule or schema identifier when implementing policy behavior.

Do not include credentials, real trust-center data, customer findings, private infrastructure
details, or exploit-enabling evidence.

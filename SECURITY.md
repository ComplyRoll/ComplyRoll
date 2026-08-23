# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use GitHub private vulnerability reporting for this repository:
<https://github.com/ComplyRoll/ComplyRoll/security/advisories/new>. If that is unavailable, email
the maintainer at the address recorded in the project's git history with the subject
`ComplyRoll security report`.

Include the ComplyRoll version, the Python version, a description of the issue, and a synthetic
or redacted reproduction. You should receive an acknowledgement within five business days.
Coordinated disclosure is appreciated; the maintainer will work with you on a fix and a public
advisory once a fix is available.

## Supported versions

ComplyRoll is pre-alpha. Only the most recent commit on `main` receives fixes. There are no
supported release branches yet.

## Sensitive input

Real assessment artifacts (CKL, CKLB, XCCDF, ARF, scanner exports) routinely contain hostnames,
addresses, finding details, and Controlled Unclassified Information (CUI) markings. Never attach
them to issues, pull requests, or advisories. Reproduce with the synthetic fixtures under
`tests/fixtures/` or a redacted copy that keeps only rule identifiers and statuses.

## Design requirements

The threat model, input-handling bounds, evidence-integrity controls, and dependency policy live
in [`docs/SECURITY.md`](docs/SECURITY.md). That document describes what the code enforces today
and what remains planned; it is not a statement of FedRAMP authorization or endorsement.

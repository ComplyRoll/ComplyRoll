# ADR 0001: Separate observations from vulnerability cases

- Status: Accepted
- Date: 2026-08-18

## Context

Scanner output describes source observations. FedRAMP VDR requires providers to track and respond
to logical vulnerabilities using service context, including reachability, exploitability,
potential agency impact, mitigation, remediation, and acceptance.

A single weakness may appear on hundreds of resources and in several tools. Conversely, two
similar scanner records may require separate cases because their exposure or customer impact is
different.

## Decision

TrustRoll will store immutable observations separately from stateful vulnerability cases.

Correlation links observations to cases through explicit events. Grouping will preserve every
source record and affected resource. Manual split and merge operations will remain auditable.

## Consequences

Benefits:

- Reingestion does not overwrite provider decisions.
- Grouped reporting remains traceable to individual resources.
- Evaluation and response history can evolve without altering source facts.
- Process failures and non-scanner weaknesses can use the same case workflow.

Costs:

- Correlation logic and storage are more complex than a flat findings table.
- Case counts cannot be assumed to equal observation counts.
- Users need clear UI and CLI explanations of grouping.

## Rejected alternative

Extending the existing flat `Finding` record with PAIN and response fields was rejected because it
would duplicate one contextual decision across every affected resource and make grouping,
history, and corrections ambiguous.

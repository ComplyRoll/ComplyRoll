## Summary

<!-- What changes and why. Cite the FedRAMP rule or schema identifier when policy or report
behavior changes. -->

## Checklist

- [ ] Tests added or updated for every behavior change.
- [ ] No real assessment artifacts, customer data, infrastructure details, or CUI in code,
      fixtures, or this description. Fixtures are synthetic.
- [ ] An ADR was added or amended under `docs/decisions/` for data-model, persistence, policy,
      or security decisions.
- [ ] Commits carry a `Signed-off-by` line (Developer Certificate of Origin, see CONTRIBUTING.md).
- [ ] `python -m unittest discover -s tests -v` passes locally.

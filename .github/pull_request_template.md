## Summary

<!-- One or two sentences: what changed and why. -->

## References

- Work item: `docs/00-WORK-ITEMS.md` → ID:
- Defect register: `docs/01-KNOWN-ISSUES.md` → ID:
- Design hand-off (UI changes only):
- Acceptance criteria ID:

## Documentation impact (required — write "none" if nothing is affected)

- [ ] README
- [ ] CHANGELOG
- [ ] Requirements / acceptance criteria (docs/01, docs/04)
- [ ] In-app help centre
- [ ] API / CLI docs
- [ ] None

## Gate evidence

| Gate | Command | Log path | Exit code | Summary |
| --- | --- | --- | --- | --- |
| Code | `tools/run_gate.sh` | | | |
| UI (if applicable) | `tools/run_ui_gate.sh` | | | |
| Documentation facts | `tools/check_docs_facts.sh` | | | |

## Checklist

- [ ] Tests cover the change and the negative path; test names cite acceptance-criteria IDs
- [ ] No passwords, tokens, private keys or real data samples committed
- [ ] `git add -A` / `git add .` not used
- [ ] Documentation impact list ticked
- [ ] Closing evidence written back to the work-item board

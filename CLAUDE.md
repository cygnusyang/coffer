## Team Protocol

Read `~/.claude/teams/PROTOCOL.md` (global) and `docs/00-协作适配.md` (this repo) before starting team work.

- **Claim first**: every work item goes on `docs/00-WORK-ITEMS.md` and is claimed (`python3 tools/workitem.py claim <ID> --owner <name> --files "<scope>"`) before work starts. Unclaimed work is not started.
- **One owner per file**: declare the `files:` scope at claim time; never edit another owner's scope concurrently.
- **Author ≠ gate runner**: whoever writes the change does not run the approving gate; use a reviewer/verifier pass.
- **Cross-team DoD**: criteria ID aligned across design/test/docs, registry closed, doc impact checklist checked, gate evidence archived.

## Agent Team Policy

For complex tasks, actively use Agent Teams.

Create an Agent Team automatically when any of the following applies:

- The task spans multiple independent modules.
- Three or more independent investigations can run in parallel.
- The task involves architecture + implementation + testing.
- Multiple independent hypotheses should be investigated.
- The task is expected to require significant repository exploration.

When creating a team:

1. The main agent acts as team lead.
2. Break the work into independent tasks first.
3. Spawn 2-5 specialized teammates.
4. Give every teammate a clear role and ownership boundary.
5. Use the shared task list to coordinate work.
6. Avoid multiple agents editing the same file simultaneously.
7. Let teammates communicate findings directly when useful.
8. The team lead reviews and integrates all results.

Do not create an Agent Team for:
- trivial edits
- single-file fixes
- simple questions
- strongly sequential tasks
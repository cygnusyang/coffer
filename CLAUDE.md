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
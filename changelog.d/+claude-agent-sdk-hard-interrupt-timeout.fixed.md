Interrupting a `claude-agent-sdk` agent, or hitting its `max_session_seconds`
limit, no longer waits for the SDK to deliver another message before taking
effect — a run blocked waiting on the model now stops when asked. The session
limit is a single deadline measured from the start of the execution, so a
steady stream of messages can no longer extend it indefinitely. Conductor
waits for the SDK to finish releasing its resources before returning and
before deleting that execution's temporary MCP configuration, so returning
after an interrupt or a timeout may take some additional time.

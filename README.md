# Tool Authorizer — Pi Extension

Intercepts **every** agent tool call and delegates authorization to a lightweight sub-agent. The sub-agent returns one of three verdicts:

- **ALLOW** — tool proceeds
- **DENY: \<reason\>** — tool blocked, a DenialUUID is generated
- **MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION** — extension gathers additional context from the session and re-spawns the sub-agent

## Dependencies

| Dependency | Type | Source |
|---|---|---|
| [`@tintinweb/pi-subagents`](https://www.npmjs.com/package/@tintinweb/pi-subagents) `^0.5.2` | runtime | npm |
| `@mariozechner/pi-coding-agent` | peer | bundled with pi |
| `@sinclair/typebox` | peer | bundled with pi |

During installation, `npm install` (or `npm ci`) is run automatically, so the `@tintinweb/pi-subagents` dependency is resolved without manual steps.

## How It Works

1. **Interception** — every tool call (`read`, `bash`, `write`, `edit`, etc.) is routed through a `tool_call` event handler.
2. **Classification** — the extension classifies the call into one of three buckets:
   - **Bypass** — tools like `ls`, `grep`, `find` that are metadata-only, or reads of recognized project source files inside the current working directory.
   - **Fast-path** — reads from trusted directories (e.g., `~/.pi/agent/skills`).
   - **Requires authorization** — everything else (writes, edits, sensitive paths, complex bash commands).
3. **Sub-agent delegation** — when authorization is required, the extension spawns the `authorizer` sub-agent with the tool name, parameters, working directory, and optional additional context.
4. **Verdict** — the sub-agent's response is parsed and acted upon.
5. **Override** — if denied, the user can supply an HMAC override (see below).

## The `approve_override` Tool

When a tool call is denied, the extension generates a **DenialUUID** and includes it in the block reason:

```
AUTHORIZER_DENIED:<uuid>:<reason>
```

The user can override a denial by computing:

```
HMAC-SHA256(sharedSecret, "<denial_uuid>:<toolName>")
```

and calling the `approve_override` tool with:

```json
{
  "denial_uuid": "<uuid-from-block-reason>",
  "mac": "<64-character-hex-digest>"
}
```

### Secret Management

- The shared secret is stored at `~/.pi/secret/authorizer-secret.txt`.
- Format: `v=1;secret=<64-hex-chars>` (32 random bytes).
- The secret is **rotated** after every successful override (version `v` increments).
- The previous secret is discarded — overrides are single-use.

> **Tip:** To retrieve the current secret for manual override computation, read the file at `~/.pi/secret/authorizer-secret.txt`.

## Possible Errors

| Symptom | Likely Cause | Fix |
|---|---|---|
| Tool calls always pass through (no authorization) | `@tintinweb/pi-subagents` not installed, or its manager symbol is unavailable | Check that the package is installed (`ls ~/.pi/agent/extensions/node_modules/@tintinweb/pi-subagents`). Run `npm install` in `~/.pi/agent/extensions/`. |
| `AUTHORIZER_DENIED:<uuid>:Authorization error: ...` | The sub-agent failed to spawn or returned an error | Check the model configured in `~/.pi/agent/agents/authorizer.md` is available. Run `/authorizer-log` for details. |
| `AUTHORIZER_DENIED:<uuid>:Authorization timed out` | Sub-agent took longer than 30 seconds | The sub-agent model may be slow or unavailable. Increase `AUTHORIZER_TIMEOUT_MS` in the extension source, or switch to a faster model in `authorizer.md`. |
| `AUTHORIZER_DENIED:<uuid>:Unparseable authorization response` | The sub-agent returned text that didn't match ALLOW/DENY/MORE CONTEXT | Check `/authorizer-log` for the full response. Adjust the `parseVerdict()` function or reinforce the response format in `authorizer.md`. |
| `AUTHORIZER_DENIED:<uuid>:Insufficient context to authorize` | Sub-agent asked for more context but nothing new was available | The extension gathers the last user message and file info. If that's insufficient, consider including more context in the `gatherMoreContext()` function. |
| Every tool call is blocked | The extension classifies everything as "needs authorization" and the authorizer sub-agent denies everything | Check `authorizer.md` rules — the default bundle allows project file reads and trivial bash commands. If the sub-agent is unreachable, the extension denies by default (fail-closed). |
| `/test-authorizer` doesn't respond | `pi-subagents` manager not available on the global symbol | The `Symbol.for("pi-subagents:manager")` must be set by the `@tintinweb/pi-subagents` extension. Ensure it is loaded (check load order in settings). |
| Invalid MAC on override attempt | The shared secret changed (e.g., race condition with another override), or the wrong data format was used | The data format is `denial_uuid + ":" + toolName` — note the colon separator, no spaces. Secrets are case-sensitive hex. |

### Fail-Closed Behavior

If the sub-agent cannot be spawned (e.g., missing agent definition, model unavailable, network error), the extension **denies** the tool call. This ensures the agent never proceeds without authorization when the security layer is malfunctioning.

## Built-In Commands

The extension registers these slash commands for runtime management:

| Command | Description |
|---|---|
| `/authorizer-log` | Show the last 10 entries from the debug log |
| `/authorizer-settings` | Show status and configuration (manager availability, secret version, pending overrides, fast-path dirs, etc.) |
| `/test-authorizer read <path>` | Manually test how the authorizer would classify a `read` tool call |
| `/test-authorizer bash <command>` | Manually test how the authorizer would classify a `bash` command |
| `/test-authorizer <tool> <key=value ...>` | Test any tool with key=value parameters |

## Fresh Install: Step-by-Step Customization Guide

After installing the extension, follow these steps to tailor it to your environment.

### 1. Customize the Authorizer Agent Model

The file `~/.pi/agent/agents/authorizer.md` is created automatically on first load from the bundled template at `~/.pi/agent/authorizer.bundle.md`. It contains a YAML frontmatter block that specifies the model:

```yaml
---
description: Authorizes tool calls for the tool-authorizer extension
tools: none
extensions: none
skills: none
prompt_mode: replace
max_turns: 1
isolated: true
model: anthropic/claude-haiku-4.5
---
```

**To change the model**, edit the `model:` field in `~/.pi/agent/agents/authorizer.md`. For example:

```yaml
model: openai/gpt-4o-mini       # Faster, cheaper, but may be less precise
model: anthropic/claude-sonnet-4-20250514  # More capable, slower
model: google/gemini-2.0-flash   # Google alternative
```

> **Important:** The authorizer uses `max_turns: 1` — it gets exactly one LLM response. It has `tools: none` — it cannot execute any tools. It is `isolated: true` — it runs in a clean context with no extensions. Use a fast, reliable model that follows formatting instructions precisely.

### 2. Customize Fast-Path Directories for the `read` Tool

The `READ_FAST_PATH_DIRS` array in the extension source file (`~/.pi/agent/extensions/tool-authorizer.ts`) lists directories whose contents are always allowed to be read without sub-agent authorization:

```typescript
const READ_FAST_PATH_DIRS: string[] = [
  join(homedir(), ".pi", "agent", "skills"),
];
```

**To add your own trusted directories**, append entries:

```typescript
const READ_FAST_PATH_DIRS: string[] = [
  join(homedir(), ".pi", "agent", "skills"),
  resolve("C:\\MyTeam\\shared-docs"),
  resolve("/home/team/shared-configs"),
];
```

All subdirectories of listed paths are included automatically. This is useful for:
- Shared documentation or config directories
- Extension/skill source directories you trust
- Read-only reference material directories

### 3. Customize Security Rules

The security rules are defined in `~/.pi/agent/agents/authorizer.md`. The default bundle includes rules for:

- **Destructive commands** — blocks `rm -rf`, `sudo`, `curl`, package installs, etc.
- **Sensitive files** — blocks reads of `.env`, `.pem`, `.key`, `~/.ssh/`, etc.
- **Blacklisted directories** — blocks reads/writes to `~/.pi/agent/agents/`
- **Allowed parent directories** — only permits reads/writes within `~/.pi/agent/extensions/`
- **Safe tool calls** — always allows `ls`, `grep`, `find`, `cat`, `git status`, etc.
- **Custom tools** — blocks tools that access external systems, modify session state, or could leak data

**To customize**, edit the relevant section in `authorizer.md`. Rules are priority-ordered (highest to lowest). If rules conflict, the higher-priority rule wins.

### 4. Customize Authorization Timeout

The default timeout for sub-agent authorization is **30 seconds**. To change it, edit the constant in `~/.pi/agent/extensions/tool-authorizer.ts`:

```typescript
const AUTHORIZER_TIMEOUT_MS = 30_000; // Change to 60_000 for 60 seconds
```

### 5. Customize Authorization Retry Limit

The extension retries up to **3 times** when the sub-agent returns "MORE CONTEXT REQUIRED". To change this:

```typescript
const MAX_AUTHORIZATION_ATTEMPTS = 3; // Increase to 5 for more retries
```

### 6. Customize Always-Bypass Tools

Tools in the `ALWAYS_BYPASS` set are never sent to the sub-agent. By default this is `grep`, `find`, `ls`:

```typescript
const ALWAYS_BYPASS = new Set(["grep", "find", "ls"]);
```

Add or remove entries based on your risk tolerance. For example, to also bypass `echo`:

```typescript
const ALWAYS_BYPASS = new Set(["grep", "find", "ls", "echo"]);
```

### 7. Customize Sensitive Path Patterns

The `SENSITIVE_PATTERNS` array controls which paths trigger automatic authorization. Edit in `~/.pi/agent/extensions/tool-authorizer.ts`:

```typescript
const SENSITIVE_PATTERNS: RegExp[] = [
  // Default patterns...
  /(^|[/\\])\.env($|\.)/i,
  /(^|[/\\])my-custom-secrets/i,  // Add your own patterns
];
```

### 8. Customize Dangerous Bash Patterns

The `DANGEROUS_BASH_PATTERNS` array controls which bash commands trigger authorization. Edit in the extension source:

```typescript
const DANGEROUS_BASH_PATTERNS: RegExp[] = [
  // Default patterns...
  /\bterraform\s+destroy\b/i,  // Add terraform destroy
  /\baws\s+s3\s+rm\b/i,       // Add AWS S3 deletion
];
```

### 9. Verify the Installation

After customizing, run these verification steps:

1. **Check the extension loaded** — look for `[tool-authorizer] Extension loaded` in pi's startup output.
2. **Check the authorizer agent was created** — verify `~/.pi/agent/agents/authorizer.md` exists.
3. **Test a safe command** — ask the agent to `ls` a directory. It should pass through without authorization.
4. **Test a risky command** — ask the agent to `rm -rf` or `curl`. It should be blocked with a DenialUUID.
5. **Test the authorizer directly** — use `/test-authorizer read C:/path/to/file` or `/test-authorizer bash rm -rf /`.
6. **Test an override** — after a denial, retrieve the secret from `~/.pi/secret/authorizer-secret.txt`, compute the HMAC, and call `approve_override`.
7. **Check the log** — use `/authorizer-log` to see recent authorization decisions.

## Architecture

```
Agent Tool Call
       │
       ▼
┌──────────────────────┐
│  classifyToolCall()  │
│  (fast-path check)   │
└──────────┬───────────┘
           │
    ┌──────┴──────┐
    │             │
  Bypass     Needs Auth
    │             │
    ▼             ▼
  Allow     ┌─────────────────────┐
            │  mgr.spawn()        │
            │  authorizer sub-agent│
            └──────────┬──────────┘
                       │
              ┌────────┴────────┐
              │                 │
           ALLOW              DENY
              │                 │
              ▼                 ▼
           Allow       ┌──────────────────┐
                       │  Block + DenialUUID│
                       └──────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ approve_override │
                     │ (HMAC check +    │
                     │  secret rotation)│
                     └─────────────────┘
```

## License

MIT

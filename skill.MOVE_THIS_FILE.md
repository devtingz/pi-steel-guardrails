---
name: approve-override
description: "Instructions for using the approve_override tool to bypass tool-authorizer denials.  This file should be placed in the proper Pi skills directory"
metadata:
  short-description: Override tool-authorizer denials with a Denial UUID and a valid HMAC-SHA256 MAC
---

# Approve Override Skill

This skill explains how to use the `approve_override` tool when the tool-authorizer extension blocks a tool call, and the authorizer sub-agent (at `~/.pi/agent/agents/authorizer.md`) has already confirmed the denial.

## Background

The **tool-authorizer** extension intercepts every agent tool call (read, write, edit, bash, etc.) and delegates authorization to a lightweight sub-agent. The sub-agent returns one of:

- `ALLOW` — tool proceeds normally
- `DENY: <reason>` — tool blocked, a DenialUUID is generated
- `MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION` — extension gathers more context and re-spawns

When the authorizer denies a tool call, the user can override the denial by computing an HMAC-SHA256 of the shared secret and supplying it via `approve_override`.

## Override Workflow

### Step 1: Read the denial UUID from the error

When a tool is blocked, the denial reason contains a UUID:

```
AUTHORIZER_DENIED:<denial_uuid>:<reason>
```

Example:
```
AUTHORIZER_DENIED:aef55d94-b7e9-46be-ab31-25e6116744f4:Path is not within any allowed parent directory
```

The UUID is `aef55d94-b7e9-46be-ab31-25e6116744f4`.

### Step 2: Compute the MAC

Use the `authorizer_override.py` script to compute the HMAC:

```bash
python authorizer_override.py \
    ~/.pi/secret/authorizer-secret.txt \
    <denial_uuid> \
    <tool_name>
```

The script reads the shared secret from `~/.pi/secret/authorizer-secret.txt`, computes:

```
HMAC-SHA256(sharedSecret_utf8, denial_uuid + ":" + toolName)
```

And outputs a 64-character hex MAC.

> **Important:** The shared secret is passed as a UTF-8 string (64 ASCII bytes), NOT hex-decoded. The `authorizer_override.py` script handles this correctly.

### Step 3: Call approve_override

Call the `approve_override` tool with the denial UUID and the computed MAC:

```
approve_override(denial_uuid="aef55d94-...", mac="6f16793653a43f31fac4c6166bbcaa887857c7a33ffaa405dbce77a43a45d7e9")
```

### Step 4: Retry the original tool call

On success, the override is registered as a whitelist entry. The next **identical tool call** (same tool name + same parameters) will be automatically allowed without authorization. The shared secret is rotated after each successful override.


## When to Use approve_override

- **Use when** the authorizer agent has correctly identified the tool call as denied but the user deems the operation safe and necessary.
- **Do not use** when the authorizer returned an "Unparseable" error — the denial was never stored and cannot be overridden. Instead, fix the authorizer sub-agent's response format to return a clean `DENY: <reason>` or `ALLOW` without preamble or markdown formatting.

## Security Model

- The shared secret is stored at `~/.pi/secret/authorizer-secret.txt` (readable only by the user).
- Each override consumes the UUID (single-use) and rotates the secret.
- The override whitelist is single-use — the next identical tool call is allowed, then the entry is deleted.
- The whitelist is in-memory only and cleared on session shutdown.

## Common Pitfalls

| Pitfall | Resolution |
|---|---|
| MAC rejected (Invalid MAC) | The shared secret may have been rotated since the MAC was computed. Inform the user that the MAC is invalid. |
| "No pending denial found" | The denial was never stored (e.g., unparseable response) or the UUID was already consumed. |
| Override approved but tool still blocked | The retry was not an exact match. Ensure the tool name and all parameters (`input.path`, `input.command`, etc.) are identical to the original denied call. |

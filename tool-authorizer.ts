   /**
    * Tool Authorizer Extension
    *
    * Intercepts every agent tool call and delegates authorization to a lightweight
    * sub-agent (defined in ~/.pi/agent/agents/authorizer.md) that runs with
    * maxTurns: 1, tools: none, prompt_mode: replace.
    *
    * On first load, automatically creates ~/.pi/agent/agents/authorizer.md from
    * the bundled template at 
    * ~/.pi/agent/extensions/tool-authorizer/authorizer.bundle.md (if the file does
    * not already exist).  AI Agents should have full access to read the sample
    * authorizer.md file here: "~/.pi/agent/extensions/tool-authorizer/authorizer.sample.md".
    *
    * The authorizer returns one of three verdicts:
    *   ALLOW                                   — tool proceeds
    *   DENY: <reason>                          — tool blocked, DenialUUID generated
    *   MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION — extension gathers context and re-spawns
    *
    * When denied, the user can override by computing:
    *   HMAC-SHA256(sharedSecret, denial_uuid + ":" + toolName)
    * and supplying it via the approve_override tool.
    *
    * Dependencies: pi-subagents extension (@tintinweb/pi-subagents)
    */

   import type { ExtensionAPI, ToolCallEvent } from "@mariozechner/pi-coding-agent";
   import { isToolCallEventType } from "@mariozechner/pi-coding-agent";
   import { Type } from "@sinclair/typebox";
   import { randomUUID, timingSafeEqual, randomBytes, createHmac } from "node:crypto";
   import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
   import { homedir } from "node:os";
   import { join, resolve, normalize } from "node:path";

   // ---------------------------------------------------------------------------
   // Constants
   // ---------------------------------------------------------------------------

   const SECRET_DIR = join(homedir(), ".pi", "secret");
   const SECRET_FILE = join(SECRET_DIR, "authorizer-secret.txt");
   const SECRET_BYTE_LENGTH = 32; // 32 bytes → 64 hex chars per secret

   const MAX_AUTHORIZATION_ATTEMPTS = 3;
   const AUTHORIZER_TIMEOUT_MS = 30_000;

   /** Debug log file within the allowed ~/.pi/agent/ path. */
   const LOG_FILE = join(homedir(), ".pi", "agent", "authorizer-log.txt");
   const MAX_LOG_LINES = 500;

   /** Path to the authorizer sub-agent definition file. */
   const AUTHORIZER_AGENT_DIR = join(homedir(), ".pi", "agent", "agents");
   const AUTHORIZER_AGENT_FILE = join(AUTHORIZER_AGENT_DIR, "authorizer.md");

   /** Path to the bundled default template shipped with this extension. */
   const AUTHORIZER_BUNDLE_FILE = join(homedir(), ".pi", "agent", "extensions", "tool-authorizer", "authorizer.bundle.md");

   /** Tools that are always safe — metadata only, no content exposure. */
   const ALWAYS_BYPASS = new Set(["grep", "find", "ls"]);

   /** Sensitive path patterns — if any match, the path is flagged. */
   const SENSITIVE_PATTERNS: RegExp[] = [
     /(^|[/\\])\.env($|\.)/i,
     /(^|[/\\])credentials/i,
     /(^|[/\\])secrets?($|[/\\])/i,
     /\.pem$/i,
     /\.key$/i,
     /\.cert$/i,
     /id_rsa$/,
     /id_dsa$/,
     /id_ecdsa$/,
     /id_ed25519$/,
     /\.netrc$/,
     /\.git-credentials$/,
     /(^|[/\\])\.aws[/\\]/,
     /(^|[/\\])\.ssh[/\\]/,
     /(^|[/\\])\.gnupg[/\\]/,
     /(^|[/\\])\.config[/\\]gcloud[/\\]/,
     /^\/etc\/shadow/,
     /^\/etc\/passwd/,
     /^\/etc\/ssl[/\\]/,
     /^\/etc\/sudoers/,
   ];

   /** Dangerous bash patterns — if any match, the command is flagged. */
   const DANGEROUS_BASH_PATTERNS: RegExp[] = [
     /\brm\s+(-rf|--recursive|-fr|-r\s*-f)\b/i,
     /\bsudo\b/,
     /\bdd\s+if=/,
     /\bmkfs\b/,
     /\bfdisk\b/,
     /\bchmod\s+777\b/,
     /\bchown\b/,
     />>?\s+\/etc\//,
     />>?\s+\/usr\//,
     />>?\s+~\/\./,
     /\bcurl\b/,
     /\bwget\b/,
     /\bapt\s+install\b/,
     /\byum\s+install\b/,
     /\bbrew\s+install\b/,
     /\bpip\s+install\b/,
     /\bnpm\s+install\s+-g\b/,
   ];

   /** Trivial bash commands that bypass authorization. */
   const TRIVIAL_BASH_PATTERNS: RegExp[] = [
     /^\s*(ls|grep|find|echo|pwd|whoami|date|which|type|cat)\b/,
     /^\s*git\s+(status|log|diff|branch|show|stash\s+list)\b/,
     /^\s*cd\b/,
     /^\s*mkdir\b/,
     /^\s*touch\b/,
   ];

   /** 
    * Directories whose contents can always be fast-pathed for "read" tool calls.
    * Supports ~ for home directory. Subdirectories are included recursively.
    * Add or remove entries here to customize the fast-path list.
    */
   const READ_FAST_PATH_DIRS: string[] = [
     join(homedir(), ".pi", "agent", "skills"),
   ];

   /** Project source file extensions — safe to read without authorization. */
   const PROJECT_FILE_EXTS = new Set([
     ".ts", ".js", ".jsx", ".tsx", ".py", ".cs", ".rs", ".go", ".rb", ".php",
     ".java", ".cpp", ".c", ".h", ".hpp", ".swift", ".kt", ".scala",
     ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
     ".xml", ".html", ".css", ".scss", ".less",
     ".sh", ".bat", ".ps1",
     ".gradle", ".props", ".sln", ".csproj",
   ]);

   // ---------------------------------------------------------------------------
   // Secret management
   // ---------------------------------------------------------------------------

   interface SecretState {
     version: number;
     secret: string; // 64 hex chars (32 bytes)
   }

   /** Read the current secret from file. Creates file on first run. */
   function loadSecret(): SecretState {
     if (!existsSync(SECRET_DIR)) {
       mkdirSync(SECRET_DIR, { recursive: true });
     }
     if (!existsSync(SECRET_FILE)) {
       const secret = generateSecret();
       writeFileSync(SECRET_FILE, `v=1;secret=${secret}`, "utf-8");
       return { version: 1, secret };
     }
     const raw = readFileSync(SECRET_FILE, "utf-8").trim();
     const vMatch = raw.match(/v=(\d+);/);
     const sMatch = raw.match(/secret=([a-f0-9]+)/i);
     if (!vMatch || !sMatch) {
       // Corrupt file — recreate
       const secret = generateSecret();
       writeFileSync(SECRET_FILE, `v=1;secret=${secret}`, "utf-8");
       return { version: 1, secret };
     }
     return { version: parseInt(vMatch[1], 10), secret: sMatch[1].toLowerCase() };
   }

   /** Atomically rotate the secret. Reads current version, writes v+1 if version hasn't changed. Returns true on success. */
   function rotateSecret(expectedVersion: number): boolean {
     if (!existsSync(SECRET_FILE)) return false;
     const raw = readFileSync(SECRET_FILE, "utf-8").trim();
     const vMatch = raw.match(/v=(\d+);/);
     if (!vMatch) return false;
     const currentVersion = parseInt(vMatch[1], 10);
     if (currentVersion !== expectedVersion) return false; // race detected

     const newSecret = generateSecret();
     writeFileSync(SECRET_FILE, `v=${expectedVersion + 1};secret=${newSecret}`, "utf-8");
     return true;
   }

   function generateSecret(): string {
     return randomBytes(SECRET_BYTE_LENGTH).toString("hex");
   }

   /** Append a timestamped entry to the debug log. Trims to MAX_LOG_LINES on each write. */
   function appendDebugLog(entry: string): void {
     try {
       const timestamp = new Date().toISOString();
       appendFileSync(LOG_FILE, `[${timestamp}] ${entry}\n`, "utf-8");
       // Trim to prevent unbounded growth
       const content = readFileSync(LOG_FILE, "utf-8");
       const lines = content.split("\n");
       if (lines.length > MAX_LOG_LINES) {
         writeFileSync(LOG_FILE, lines.slice(lines.length - MAX_LOG_LINES).join("\n"), "utf-8");
       }
     } catch { /* best-effort */ }
   }

   /** Return the last N log lines as a single string. */
   function tailDebugLog(n: number): string {
     try {
       if (!existsSync(LOG_FILE)) return "(log file does not exist yet)";
       const content = readFileSync(LOG_FILE, "utf-8");
       const lines = content.trim().split("\n");
       return lines.slice(-n).join("\n");
     } catch (e: any) {
       return `(error reading log: ${e?.message ?? "unknown"})`;
     }
   }

   /** Compute HMAC-SHA256 hex digest. */
   function computeHMAC(secret: string, data: string): string {
     return createHmac("sha256", secret).update(data, "utf-8").digest("hex");
   }

   /**
    * Ensure the authorizer agent file exists. If ~/.pi/agent/agents/authorizer.md
    * does not already exist, it is created from the bundled template at
    * ~/.pi/agent/authorizer.bundle.md.  This runs once per session_start, so
    * existing customizations are never overwritten.
    */
   function ensureAuthorizerAgent(): void {
     if (existsSync(AUTHORIZER_AGENT_FILE)) {
       return; // Already exists — never overwrite
     }
     if (!existsSync(AUTHORIZER_BUNDLE_FILE)) {
       console.log("[tool-authorizer] Bundle file not found, skipping auto-create:", AUTHORIZER_BUNDLE_FILE);
       return;
     }
     try {
       if (!existsSync(AUTHORIZER_AGENT_DIR)) {
         mkdirSync(AUTHORIZER_AGENT_DIR, { recursive: true });
       }
       const content = readFileSync(AUTHORIZER_BUNDLE_FILE, "utf-8");
       writeFileSync(AUTHORIZER_AGENT_FILE, content, "utf-8");
       console.log("[tool-authorizer] Created default authorizer agent:", AUTHORIZER_AGENT_FILE);
     } catch (err: any) {
       console.log("[tool-authorizer] Failed to create authorizer agent:", err?.message ?? "unknown");
     }
   }

   // ---------------------------------------------------------------------------
   // Fast-path classification
   // ---------------------------------------------------------------------------

   interface Classification {
     needsAuth: boolean;
     sensitivePaths?: string[];
     reason?: string;
   }

   /** Resolve a path and normalize it for pattern matching. */
   function normalizeToolPath(rawPath: string): string {
     try {
       return resolve(normalize(rawPath));
     } catch {
       return rawPath;
     }
   }

   /** Check if a path matches any sensitive pattern. */
   function isSensitivePath(path: string): boolean {
     const normalized = normalizeToolPath(path);
     for (const pattern of SENSITIVE_PATTERNS) {
       if (pattern.test(normalized)) return true;
     }
     return false;
   }

   /** Check if a resolved path is inside any of the fast-path directories. */
   function isInsideFastPathDir(path: string): boolean {
     const resolvedPath = normalizeToolPath(path);
     for (const dir of READ_FAST_PATH_DIRS) {
       const resolvedDir = normalizeToolPath(dir);
       if (
         resolvedPath === resolvedDir ||
         resolvedPath.startsWith(resolvedDir + "/") ||
         resolvedPath.startsWith(resolvedDir + "\\")
       ) {
         return true;
       }
     }
     return false;
   }

   /** Check if a resolved path is within the project working directory. */
   function isInsideProject(cwd: string, path: string): boolean {
     try {
       const resolvedCwd = resolve(normalize(cwd));
       const resolvedPath = resolve(normalize(path));
       // Path is inside project if it equals cwd or starts with cwd + path separator
       return (
         resolvedPath === resolvedCwd ||
         resolvedPath.startsWith(resolvedCwd + "/") ||
         resolvedPath.startsWith(resolvedCwd + "\\")
       );
     } catch {
       return false;
     }
   }

   /** Check if a path is a regular project source file within the project directory. */
   function isProjectSourceFile(path: string, cwd: string): boolean {
     const lower = path.toLowerCase();
     for (const ext of PROJECT_FILE_EXTS) {
       if (lower.endsWith(ext)) {
         // Only treat as safe if the file is inside the project working directory
         return isInsideProject(cwd, path);
       }
     }
     return false;
   }

   /** Check if a bash command references an absolute path (potential outside-cwd access). */
   function referencesAbsolutePath(command: string): boolean {
     // Look for patterns like C:\..., /absolute/path, or ~/path
     // This is a heuristic — not perfect, but catches obvious outside-project access
     return /(?<![\w])[A-Za-z]:[/\\]/.test(command) ||  // e.g., C:\...
            /(?<![\w-])\/[^\s]+/.test(command) ||         // e.g., /etc/passwd
            /(?<![\w])~[/\\]/.test(command);              // e.g., ~/somewhere
   }

   /** Check if a bash command is trivial/read-only. */
   function isTrivialBashCommand(command: string): boolean {
     for (const pattern of TRIVIAL_BASH_PATTERNS) {
       if (pattern.test(command)) return true;
     }
     return false;
   }

   /** Check if a bash command contains dangerous patterns. */
   function hasDangerousBashPattern(command: string): boolean {
     for (const pattern of DANGEROUS_BASH_PATTERNS) {
       if (pattern.test(command)) return true;
     }
     return false;
   }

   /** Classify a tool call to determine if authorization is needed. */
   function classifyToolCall(toolName: string, input: Record<string, unknown>, cwd: string): Classification {
     // Always bypass: metadata-only tools (non-standard, no path param to check)
     if (ALWAYS_BYPASS.has(toolName)) {
       return { needsAuth: false };
     }

     if (toolName === "read") {
       const path = String(input.path ?? "");
       if (isSensitivePath(path)) {
         return { needsAuth: true, sensitivePaths: [path], reason: "Sensitive file path" };
       }
       // Fast-path: allow reads from explicitly trusted directories (e.g., skills, pi-mono)
       if (isInsideFastPathDir(path)) {
         return { needsAuth: false };
       }
       if (isProjectSourceFile(path, cwd)) {
         return { needsAuth: false };
       }
       // Unknown extension or no extension — authorize to be cautious
       return { needsAuth: true, sensitivePaths: [path], reason: "Unrecognized file type" };
     }

     if (toolName === "bash") {
       const command = String(input.command ?? "");
       if (isTrivialBashCommand(command)) {
         // Even trivial commands can access files outside the project via absolute paths
         if (referencesAbsolutePath(command)) {
           return { needsAuth: true, reason: "Trivial command referencing absolute path — may access files outside project" };
         }
         return { needsAuth: false };
       }
       if (hasDangerousBashPattern(command)) {
         return { needsAuth: true, reason: "Potentially destructive command" };
       }
       // Complex/multi-part command — authorize to be safe
       return { needsAuth: true, reason: "Complex command requires authorization" };
     }

     // write, edit, and any custom/extension tools: always authorize
     return { needsAuth: true, reason: "Write operation requires authorization" };
   }

   // ---------------------------------------------------------------------------
   // Authorization prompt builder
   // ---------------------------------------------------------------------------

   function buildAuthorizationPrompt(
     toolName: string,
     params: Record<string, unknown>,
     cwd: string,
     additionalContext?: string,
   ): string {
     const lines: string[] = [];
     lines.push(`Tool: ${toolName}`);
     lines.push(`Parameters: ${JSON.stringify(params, null, 2)}`);
     lines.push(`Working Directory: ${cwd}`);

     if (additionalContext) {
       lines.push("");
       lines.push("Additional Context:");
       lines.push(additionalContext);
     }

     lines.push("");
     lines.push("Respond with exactly one of:");
     lines.push("ALLOW");
     lines.push("DENY: <reason>");
     lines.push("MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION");

     return lines.join("\n");
   }

   // ---------------------------------------------------------------------------
   // Context gathering (for MORE CONTEXT REQUIRED responses)
   // ---------------------------------------------------------------------------

   function gatherMoreContext(event: ToolCallEvent, ctx: any): string | null {
     const parts: string[] = [];

     // Last user message
     try {
       const entries = ctx.sessionManager?.getEntries?.() ?? [];
       for (let i = entries.length - 1; i >= 0; i--) {
         const e = entries[i];
         if (e.type === "message" && e.message?.role === "user") {
           const text = typeof e.message.content === "string"
             ? e.message.content
             : (Array.isArray(e.message.content)
               ? e.message.content.map((c: any) => c.text ?? "").join(" ")
               : "");
           const truncated = text.slice(0, 300);
           if (truncated.trim()) {
             parts.push(`Last user message: ${truncated}`);
             break;
           }
         }
       }
     } catch { /* ignore */ }

     // Session name
     try {
       const name = ctx.sessionManager?.getSessionFile?.();
       if (name) parts.push(`Session: ${name}`);
     } catch { /* ignore */ }

     // File info for path-based tools
     if (event.input && typeof event.input === "object") {
       const input = event.input as Record<string, unknown>;
       if (input.path) {
         const resolved = normalizeToolPath(String(input.path));
         parts.push(`Resolved path: ${resolved}`);
         parts.push(`Path exists: ${existsSync(resolved)}`);
         if (isSensitivePath(String(input.path))) {
           parts.push("Path matches sensitive pattern");
         }
       }
       if (input.command) {
         const cmd = String(input.command);
         parts.push(`Command type: ${hasDangerousBashPattern(cmd) ? "potentially destructive" : "unknown"}`);
       }
     }

     if (parts.length === 0) return null;

     const result = parts.join("\n");
     // Keep under 500 words
     const wordCount = result.split(/\s+/).length;
     if (wordCount > 500) {
       const words = result.split(/\s+/);
       return words.slice(0, 500).join(" ") + " [truncated]";
     }
     return result;
   }

   // ---------------------------------------------------------------------------
   // Verdict parsing with markdown/preamble resilience
   // ---------------------------------------------------------------------------

   /**
    * Parse the authorizer sub-agent's response, stripping markdown and
    * locating the verdict keyword despite preamble/formatting.
    *
    * Handles:
    *   "ALLOW"
    *   "**ALLOW**"
    *   "I've reviewed this. ALLOW"
    *   "DENY: reason"
    *   "**DENY:** reason"
    *   "**DENY: reason**"
    *   "My response stands: **DENY: Path is outside...**"
    *   "MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION"
    *
    * Fallbacks (when none of the above match cleanly):
    *   "**ALLOWED**" or "The tool call is ALLOWED."    → "ALLOW"
    *   "**DENIED**" or "DENIED: reason"                → "DENY: reason"
    */
   function parseVerdict(raw: string): string | null {
     // Strip markdown formatting characters, collapse whitespace
     const clean = raw.replace(/[*_`~#\[\]]/g, "").replace(/\s+/g, " ").trim();

     // 1. ALLOW — word-boundary match (not ALLOWED, DISALLOW, etc.)
     if (/\bALLOW\b/.test(clean)) return "ALLOW";

     // 2. DENY: — capture everything after the colon as the reason
     const denyMatch = clean.match(/DENY\s*:\s*(.*)/);
     if (denyMatch) return "DENY: " + denyMatch[1].trim();

     // 3. MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION
     if (/MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION/.test(clean)) {
       return "MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION";
     }

     // 4. Fallback: "ALLOWED" — the authorizer sometimes appends "ED"
     if (/\bALLOWED\b/.test(clean)) return "ALLOW";

     // 5. Fallback: "DENIED" (without a colon) — map to DENY with generic reason
     const deniedMatch = clean.match(/DENIED(?:\s*:\s*(.*))?/);
     if (deniedMatch) return "DENY: " + (deniedMatch[1] ?? "DENIED").trim();

     return null;
   }

   // ---------------------------------------------------------------------------
   // Extension entry point
   // ---------------------------------------------------------------------------

   export default function (pi: ExtensionAPI) {
     let secretState: SecretState = loadSecret();
     let abortControllers = new Set<AbortController>();
     const pendingDenials = new Map<string, { toolName: string; denialUuid: string; input: Record<string, unknown> }>();
     const overrideWhitelist = new Map<string, { toolName: string; input: Record<string, unknown> }>();

     // Log startup
     console.log("[tool-authorizer] Extension loaded");

     // pi-subagents manager lives on a global Symbol. We check it lazily at each
     // tool_call rather than relying on startup events, polling, or load order.
     const MANAGER_KEY = Symbol.for("pi-subagents:manager");

     // ---- session_start: reload secret from file, ensure authorizer agent ----
     pi.on("session_start", async () => {
       secretState = loadSecret();
       ensureAuthorizerAgent();
     });

     // ---- tool_call: main authorization handler ----
     pi.on("tool_call", async (event: ToolCallEvent, ctx: any) => {
       const { toolName, toolCallId, input } = event;

       // Just-in-time check: if pi-subagents manager isn't available, pass through.
       // Uses mgr.spawn (the fundamental capability always present on the symbol)
       // rather than spawnAndWait to avoid depending on a specific symbol shape.
       const mgr = (globalThis as any)[MANAGER_KEY];
       if (!mgr?.spawn) {
         return;
       }

       // Classify the tool call with project working directory context
       const classification = classifyToolCall(toolName, input as Record<string, unknown>, ctx.cwd);

       // Check override whitelist before spawning the authorizer
       const whitelistKey = JSON.stringify({ toolName, input });
       if (overrideWhitelist.has(whitelistKey)) {
         overrideWhitelist.delete(whitelistKey);
         appendDebugLog(`OVERRIDE_ALLOW tool=${toolName} via whitelist`);
         return; // Tool proceeds — single-use override consumed
       }

       if (!classification.needsAuth) {
         return; // Allow — no authorization needed
       }

       // Authorization loop
       let additionalContext: string | undefined;
       let attempts = 0;

       while (attempts < MAX_AUTHORIZATION_ATTEMPTS) {
         attempts++;

         // Build prompt
         const prompt = buildAuthorizationPrompt(toolName, input as Record<string, unknown>, ctx.cwd, additionalContext);

         // Spawn with timeout
         const controller = new AbortController();
         appendDebugLog(`SPAWN tool=${toolName} attempt=${attempts} params=${JSON.stringify(input)}`);
         abortControllers.add(controller);
         const timeoutId = setTimeout(() => controller.abort(), AUTHORIZER_TIMEOUT_MS);

         // Spawn via mgr.spawn + mgr.getRecord + await promise instead of
         // relying on spawnAndWait. This works regardless of whether the
         // global symbol exposes spawnAndWait — making us truly load-order-safe.
         let record: any;
         try {
           const authId = mgr.spawn(pi, ctx, "authorizer", prompt, {
             maxTurns: 1,
             description: "Authorize tool",
             isBackground: false,
           });
           const authRecord = mgr.getRecord(authId);
           if (authRecord?.promise) {
             await authRecord.promise;
           }
           record = mgr.getRecord(authId);
         } catch (err: any) {
           clearTimeout(timeoutId);
           abortControllers.delete(controller);
           // On error, deny to be safe
           const uuid = randomUUID();
           return {
             block: true,
             reason: `AUTHORIZER_DENIED:${uuid}:Authorization error: ${err?.message ?? "unknown"}`,
           };
         } finally {
           clearTimeout(timeoutId);
           abortControllers.delete(controller);
         }

         // ── Parse verdict with resilience to preamble/markdown ──────────────
         const verdict = parseVerdict(record?.result ?? "");

         if (verdict === "ALLOW") {
           appendDebugLog(`ALLOW tool=${toolName}`);
           return; // Tool proceeds
         }

         if (verdict?.startsWith("DENY:")) {
           const reason = verdict.slice(5).trim();
           const uuid = randomUUID();
           // Store denial with full input for possible override
           pendingDenials.set(uuid, { toolName, denialUuid: uuid, input: input as Record<string, unknown> });
           appendDebugLog(`DENY tool=${toolName} uuid=${uuid} reason=${reason}`);
           return {
             block: true,
             reason: `AUTHORIZER_DENIED:${uuid}:${reason}`,
           };
         }

         if (verdict === "MORE CONTEXT REQUIRED TO EVALUATE AUTHORIZATION") {
           additionalContext = gatherMoreContext(event, ctx);
           appendDebugLog(`MORE_CONTEXT tool=${toolName} hasContext=${!!additionalContext}`);
           if (!additionalContext) {
             // Nothing new to provide — deny
             const uuid = randomUUID();
             return {
               block: true,
               reason: `AUTHORIZER_DENIED:${uuid}:Insufficient context to authorize`,
             };
           }
           // Loop and re-spawn with additional context
           continue;
         }

         // Unparseable response — deny, include the full response text for debugging
         const uuid = randomUUID();
         const trimmedVerdict = (record?.result ?? "").trim().slice(0, 500);
         appendDebugLog(`UNPARSEABLE tool=${toolName} uuid=${uuid} response=${trimmedVerdict}`);
         return {
           block: true,
           reason: `AUTHORIZER_DENIED:${uuid}:Unparseable authorization response. Agent replied:\n---\n${trimmedVerdict}\n---`,
         };
       }

       // Exceeded max attempts — deny
       const uuid = randomUUID();
       appendDebugLog(`TIMEOUT tool=${toolName} uuid=${uuid} attempts=${MAX_AUTHORIZATION_ATTEMPTS}`);
       return {
         block: true,
         reason: `AUTHORIZER_DENIED:${uuid}:Authorization timed out (${MAX_AUTHORIZATION_ATTEMPTS} attempts)`,
       };
     });

     // ---- approve_override tool ----
     pi.registerTool({
       name: "approve_override",
       label: "Approve Override",
       description:
         "Override a tool call denial by providing a valid HMAC-SHA256 MAC. " +
         "The user computes: HMAC-SHA256(sharedSecret, denial_uuid + \":\" + toolName) " +
         "and provides the 64-character hex digest. On success, the next identical " +
         "tool call (same toolName + parameters) is automatically allowed, and the " +
         "shared secret is rotated.",
       parameters: Type.Object({
         denial_uuid: Type.String({ description: "The DenialUUID from the denial reason" }),
         mac: Type.String({ description: "64-character hex HMAC-SHA256 digest" }),
       }),
       async execute(toolCallId: string, params: { denial_uuid: string; mac: string }, signal: AbortSignal | undefined, onUpdate: any, _ctx: any) {
         const { denial_uuid, mac } = params;
         const denial = pendingDenials.get(denial_uuid);
         if (!denial) {
           return {
             content: [{ type: "text", text: `No pending denial found for UUID "${denial_uuid}". It may have expired or already been used.` }],
             isError: true,
           };
         }

         // Compute expected MAC: HMAC-SHA256(secret, denial_uuid + ":" + toolName)
         const data = `${denial_uuid}:${denial.toolName}`;
         const expectedMac = computeHMAC(secretState.secret, data);

         // Constant-time comparison
         if (expectedMac.length !== mac.length || !timingSafeEqual(Buffer.from(expectedMac, "hex"), Buffer.from(mac, "hex"))) {
           return {
             content: [{ type: "text", text: `Invalid MAC. The HMAC did not match. Verify the shared secret and data format: denial_uuid + ":" +
 toolName` }],
             isError: true,
           };
         }

         // Valid! Move the denial to the override whitelist, then rotate the secret
         const whitelistKey = JSON.stringify({ toolName: denial.toolName, input: denial.input });
         overrideWhitelist.set(whitelistKey, { toolName: denial.toolName, input: denial.input });
         pendingDenials.delete(denial_uuid);

         const currentVersion = secretState.version;
         if (rotateSecret(currentVersion)) {
           secretState = loadSecret(); // re-read new state
         }

         return {
           content: [{ type: "text", text: `Override approved. The denied tool call (${denial.toolName}) will be automatically allowed on retry. The agent should now retry the tool call with the exact same parameters.` }],
           isError: false,
         };
       },
     });

     // ---- /authorizer-log command - show recent debug log entries ----
     pi.registerCommand("authorizer-log", {
       description: "Show the last 10 entries from the authorizer debug log",
       handler: async (_args: string, ctx: any) => {
         const lines = tailDebugLog(10);
         ctx.ui.notify(`Authorizer Debug Log (last 10 entries)\n─────────────────────────────────────\n${lines}`, "info");
       },
     });

     // ---- register a /authorizer-settings command for runtime management ----
     pi.registerCommand("authorizer-settings", {
       description: "Show tool-authorizer status and configuration",
       handler: async (_args: string, ctx: any) => {
         const statusLines = [
           `Tool Authorizer Status`,
           `─────────────────────`,
           `Manager available: ${!!(globalThis as any)[MANAGER_KEY]?.spawn}`,
           `Log file: ${LOG_FILE}`,
           `Secret file: ${SECRET_FILE}`,
           `Secret version: ${secretState.version}`,
           `Pending overrides: ${pendingDenials.size}`,
           `Authorization timeout: ${AUTHORIZER_TIMEOUT_MS}ms`,
           `Max authorization attempts: ${MAX_AUTHORIZATION_ATTEMPTS}`,
           `Fast-path bypass tools: ${[...ALWAYS_BYPASS].join(", ")}`,
           `Read fast-path dirs: ${READ_FAST_PATH_DIRS.join(" | ")}`,
           `Sensitive path patterns: ${SENSITIVE_PATTERNS.length}`,
           `Dangerous bash patterns: ${DANGEROUS_BASH_PATTERNS.length}`,
         ];
         ctx.ui.notify(statusLines.join("\n"), "info");
       },
     });

     // ---- /test-authorizer command - manually test the authorizer ----
     pi.registerCommand("test-authorizer", {
       description: "Manually test the authorizer agent. Usage: /test-authorizer <toolName> <params...>\n  read: /test-authorizer read C:/path/to/file\n  bash: /test-authorizer bash some command here\n  Other tools: /test-authorizer write path=.env content=secret",
       handler: async (args: string, ctx: any) => {
         const mgr = (globalThis as any)[MANAGER_KEY];

         // Parse args: first token is tool name, rest are params
         const trimmed = args.trim();
         if (!trimmed) {
           ctx.ui.notify(
             "Usage: /test-authorizer <toolName> <params...>\n" +
             "Examples:\n" +
             "  /test-authorizer read C:/path/to/file\n" +
             "  /test-authorizer bash rm -rf /\n" +
             "  /test-authorizer write path=.env content=secret",
             "info"
           );
           return;
         }

         const spaceIdx = trimmed.indexOf(" ");
         const toolName = spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx);
         const paramText = spaceIdx === -1 ? "" : trimmed.slice(spaceIdx + 1).trim();

         // Build params object
         const params: Record<string, string> = {};
         if (toolName === "read" && paramText && !paramText.includes("=")) {
           // Positional: first arg is the path
           params.path = paramText;
         } else if (toolName === "bash" && paramText) {
           // Positional: remaining text is the command
           params.command = paramText;
         } else {
           // Key=value pairs
           for (const part of paramText.split(/\s+/)) {
             if (!part) continue;
             const eqIdx = part.indexOf("=");
             if (eqIdx === -1) {
               params[part] = "true";
             } else {
               params[part.slice(0, eqIdx)] = part.slice(eqIdx + 1);
             }
           }
         }

         ctx.ui.setStatus("test-authorizer", `Authorizing ${toolName}...`);

         const prompt = buildAuthorizationPrompt(toolName, params, ctx.cwd);

         try {
           const testId = mgr.spawn(pi, ctx, "authorizer", prompt, {
             maxTurns: 1,
             description: `Test: ${toolName}`,
             isBackground: false,
           });
           const testRecord = mgr.getRecord(testId);
           if (testRecord?.promise) {
             await testRecord.promise;
           }
           const record = mgr.getRecord(testId);

           const verdict = (record?.result ?? "").trim();
           ctx.ui.setStatus("test-authorizer", "");

           ctx.ui.notify(
             `Verdict for ${toolName}:\n` +
             `Parameters: ${JSON.stringify(params)}\n` +
             `─────────────────────\n` +
             `${verdict || "(empty response)"}`,
             verdict === "ALLOW" ? "success" :
             verdict.startsWith("DENY") ? "error" :
             "warning"
           );
         } catch (err: any) {
           ctx.ui.setStatus("test-authorizer", "");
           ctx.ui.notify(`Authorizer error: ${err?.message ?? "unknown"}`, "error");
         }
       },
     });

     // ---- session_shutdown: cleanup ----
     pi.on("session_shutdown", async () => {
       // Abort any pending authorizations
       for (const controller of abortControllers) {
         try { controller.abort(); } catch { /* ignore */ }
       }
       abortControllers.clear();
       pendingDenials.clear();
       overrideWhitelist.clear();
     });
   }

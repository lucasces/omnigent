# kiro-native: tmux/screen-scraping → `kiro-cli acp` — analysis & implementation plan

Author: analysis sub-agent · Date: 2026-09-16
Repo: `~/personal/omnigent`, branch `custom-features`
Reference: KiroCrew clone at `/tmp/kirocrew`
Local binary under test: **kiro-cli 2.20.1** (`/home/lces/.nix-profile/bin/kiro-cli`, IAM Identity Center session)

**Status: Phase 0 spike complete (§12); implementation round 1 shipped (§14). Additive only — `kiro-native` untouched.**

---

## 0. Executive summary

The briefing framed this as "port KiroCrew's ACP client into our harness". That is **not** the right plan:

> **Omnigent already owns a mature, production generic ACP client** — `omnigent/inner/acp_executor.py` (1685 lines, `class AcpExecutor(Executor)`) — which already spawns an arbitrary CLI over JSON-RPC 2.0 stdio, runs `initialize` / `session/new` / `session/prompt`, streams `session/update`, and routes `session/request_permission` through Omnigent's TOOL_CALL policy **and** the same human-consent elicitation bridge that `claude-sdk` uses.

**Phase 0 has now proven this end to end against the real kiro-cli, with zero code changes** (§12.6): the unmodified `AcpExecutor` drove `kiro-cli acp --agent <profile>`, streamed text deltas, raised a real approval card with kiro's own `[Yes, Always, No]` buttons, and both allow and reject round-tripped correctly.

Second headline: **this cannot be an in-place replacement of `kiro-native`.** `kiro-native` is a *terminal-UI* harness (`WARM_REATTACH`, embedded pane). An ACP harness is headless and `COLD_ONLY`. The plan is a **new sibling harness** alongside the existing one. See §7.

Scope estimate: **Medium** (§10).

---

## 1. Corrections to the briefing (evidence-backed)

| Briefing said | Reality | Evidence |
|---|---|---|
| `executor.py` / `orchestration.py` live in `omnigent/harnesses/kiro_native/` | They do not. That dir holds only `bridge.py`, `main.py`, `permissions.py`, `session_forwarder.py` | `ls omnigent/harnesses/kiro_native/` |
| `KiroNativeExecutor` is a substantial contract | It is **115 lines** and nearly empty | `omnigent/inner/kiro_native_executor.py` |
| `orchestration.py` is part of the harness | It is `omnigent/runner/native/orchestration.py`, 399 KB, generic to all native harnesses | `ls omnigent/runner/native/` |
| We must port KiroCrew's ACP client | We already have one, plus vendor ACP rows (`devin`, `grok`, `jcode`) | `omnigent/inner/acp_executor.py`, `omnigent/acp_cli_harnesses.py` |
| KiroCrew's `acp/client.py` is a small clean client | It is **11,978 lines / 648 KB**, mostly pods/sandbox/toolbox-shim/OAuth remapping | `wc -l /tmp/kirocrew/src/kiro_crew/acp/client.py` |
| KiroCrew's "single sequential loop with inline `await`" is the model to copy | **Inline `await` is precisely the thing to avoid** — it head-of-line blocks concurrent approvals (§12.5, proven) | `acp_executor.py:1623` + `probe_concurrency.py` |

**Provenance caveat on the KiroCrew clone:** HEAD `1b335cf`, authored ~7 min before the clone, PR `#11325`. I could not verify the repo's public existence or licence from this session. KiroCrew is used **only** as a corroborating reference; every load-bearing claim below is verified against our own code or live kiro-cli. Notably, its one protocol claim that mattered turned out to be **wrong for 2.20.1** (§12.1).

---

## 2. What the current harness actually does

`omnigent/harnesses/kiro_native/` — 4,512 lines.

### 2.1 `bridge.py` (1,655 lines)
tmux lifecycle (`capture-pane`/`send-keys`), ready detection, `inject_user_message()`, the agent-profile writer (`write_kiro_agent_profile` → `<workspace>/.kiro/agents/<name>.json`, name = sha256 digest of session id), orphan sweeping, workspace MCP config, and all the menu/trust-scope keystroke navigation helpers.

### 2.2 `permissions.py` (1,063 lines) — "TUI ACP recorder → web elicitation"
Already parses genuine ACP frames:
```python
@dataclass(frozen=True)
class KiroPermissionRequest:
    request_id: str; tool_call_id: str; title: str; accept_option_id: str
```
**The read side is already structured ACP; the write side is keystrokes into a focused TUI.** That asymmetry is the root cause of every bug hunted today — and §12.5 now shows kiro delivers concurrent, *out-of-order* requests, which is fatal for positional keystrokes and harmless for id-addressed replies.

### 2.3 `session_forwarder.py` (1,112 lines)
Polls `~/.kiro/sessions/cli` every 0.7 s and replays messages/tool calls as `external_conversation_item`s. **In ACP this file has no reason to exist** — `session/update` delivers the same content on the wire (§12.2 proves the frames arrive).

### 2.4 `kiro_native_executor.py` (115 lines)
`supports_streaming() -> False`, injects text, yields `TurnComplete(response=None)`. The whole external contract — trivially small, but shaped by the TUI.

### 2.5 Declared capabilities
`kiro-native` = `NATIVE_TUI, APPROVAL_MIRROR, WARM_REATTACH, streaming=False`; `acp` = `ACP_SUBPROCESS, SSE_PERMISSION, COLD_ONLY, streaming=True`. Four capabilities change; `WARM_REATTACH → COLD_ONLY` is user-visible (§7). **§12.2 shows `streaming=False` is a TUI artifact — ACP mode does stream.**

---

## 3. The target machinery we already own

### 3.1 `AcpExecutor` permission path
`_decide_permission()`: TOOL_CALL policy (DENY blocks; ASK defers, failing **closed** with no handler) → elicitation via `_elicitation_choice_handler` (agent's own options as buttons) or a yes/no fallback → `_permission_outcome()` echoes the chosen `optionId`, only after confirming the agent offered it.

`_scoped_options()` requires ≥2 options, non-blank unique labels, and a `reject_*`. **Kiro satisfies this exactly** — verified against a real frame in §12.4.

### 3.2 Bubbling — free, identical to claude-sdk
`_executor_adapter.py` installs both bridges onto any executor exposing the slots (lines 192-196); `_stable_elicitation_choice_handler` ends in `await ctx.elicit(elicitation_id, params)` — the generic sub-agent → coordinator → human primitive. **No `request_id` → pending-approval registry needs designing**: correlation is a Python `await` frame, and the reply is addressed by the JSON-RPC `id`.

### 3.3 The declarative harness catalog
`omnigent/acp_cli_harnesses.py`: "add one row and its docs; do not add a new inner module, registry entries, or a per-harness spawn-env builder."

### 3.4 The per-agent escape hatch
`_build_acp_spawn_env()` accepts an embedded agent in `spec.executor.config["acp_agent"]` with keys `name`, `command`, `model`, `session_id_mode`, `send_model`, `omnigent_mcp`, `inject_system_prompt`, `env_passthrough`. This is the Phase-0 vehicle and the per-agent feature flag.

---

## 4. The three gaps — REVISED after Phase 0

| Gap | Pre-spike belief | Post-spike verdict |
|---|---|---|
| **A. Protocol dialect** | Top blocker; kiro needs `"2025-08-22"` | **REFUTED.** Integer `1` works (§12.1). No `AcpExtension.protocol_version` needed. |
| **B. Per-session `--agent`** | Needs plumbing | **CONFIRMED, trivial.** Fold into `HARNESS_ACP_COMMAND` via `shlex.join`; no `acp_harness.py` change. |
| **C. MCP via profile** | Likely | **CONFIRMED** (§12.3). Profile is the channel; `session/new.mcpServers` was `[]` and the server still loaded. |

**Two NEW gaps found by the spike, both more important than the originals:**

| Gap | Severity | Summary |
|---|---|---|
| **D. Tool-name/argument extraction** | **HIGH — security-relevant** | `_extract_tool_call` returns kiro's `title` (e.g. `"Running: echo SPIKE_DENIED"`), not the tool name. Policy rules keyed on `shell`/`sys_os_shell` **silently never match** (§12.4). |
| **E. Serialized approvals** | Medium — UX/throughput | kiro fans out concurrent requests; `acp_executor.py:1623` handles them with an inline `await`, so cards appear strictly one at a time (§12.5, proven). |

---

## 5. File-by-file plan (revised)

### Created
| File | Purpose |
|---|---|
| `omnigent/inner/kiro/__init__.py`, `extension.py`, `harness.py` | Vendor package (mirrors `omnigent/inner/devin/`). The extension now exists for **Gap D** (tool-name resolution), not protocol version. |
| `omnigent/inner/kiro/profile.py` | Profile writer moved out of `bridge.py`; also emits `mcpServers`. |
| `tests/inner/test_kiro_acp_harness.py`, `tests/e2e/test_kiro_acp_e2e.py` | New tests (§8). |

### Modified
| File | Change |
|---|---|
| `omnigent/inner/acp_extension.py` | **Additive**: a tool-identity resolver field (Gap D). *No* `protocol_version` field — Gap A is refuted. |
| `omnigent/inner/acp_executor.py` | (a) `_extract_tool_call` consults the extension's resolver; (b) line 1623 inline `await` → tracked `asyncio.create_task` (Gap E). |
| `omnigent/runtime/workflow.py` | Kiro row: write the session profile, append `--agent <name>` to `HARNESS_ACP_COMMAND`. |
| `omnigent/acp_cli_harnesses.py` | One row: `"kiro"` → `args=("acp",)`, `omnigent_mcp=False`. |
| `omnigent/spec/*` | Carry the ACP-vs-TUI opt-in flag. |

### Deleted (Phase 4)
`session_forwarder.py` (1,112), `permissions.py` (1,063), ~1,300 of `bridge.py`, `kiro_native_executor.py` + `kiro_native_harness.py` (135). **Net ≈ −3,600 / +250 lines.**

---

## 6. Approval flow, end to end (verified in §12.6)

```
kiro-cli acp --(request id=<uuid>)--> session/request_permission
  AcpExecutor queue consumer → _respond_to_agent_request
  _extract_tool_call  → (tool_name, tool_input)     [Gap D: needs _meta resolution]
  _decide_permission  → policy → _ask_user
     _scoped_options → ['Yes','Always','No']        [VERIFIED on a real frame]
     → ExecutorAdapter._stable_elicitation_choice_handler → ctx.elicit(...)
        └─ sub-agent → coordinator → human (SAME path as claude-sdk)
  _permission_outcome → {"outcome":{"outcome":"selected","optionId":"allow_once"}}
  reply addressed to <uuid>                          [VERIFIED accepted by kiro]
```

---

## 7. Incremental migration

Ship a **sibling harness**; never touch `kiro-native-ui` or production agents.

- **Phase 0 — spike (DONE, §12).** Zero diff. Five risks retired.
- **Phase 1 — Gap D + Gap E** in `acp_executor.py` / `acp_extension.py`. These are prerequisites, not niceties: Gap D weakens policy enforcement.
- **Phase 2 — harness row + vendor wrap.** `kiro` (ACP) and `kiro-native` (TUI) coexist.
- **Phase 3 — per-agent opt-in**, exactly like `kiro_agent_profile: true` (`9e6df68dc`). Flip specialists one at a time.
- **Phase 4 — deprecate**: delete `permissions.py`, `session_forwarder.py`, strip `bridge.py`.

---

## 8. Test plan

### 8.1 Fixtures — now available for free
The spike captured real kiro-cli frames (handshake, `tool_call`, `tool_call_update`, `agent_message_chunk`, `session/request_permission` for both an MCP tool and the builtin shell tool, plus `_meta.trustOptions`). Record these as JSONL fixtures and replay them against `AcpExecutor` with a fake subprocess — the same technique KiroCrew uses (`test/fixtures/acp_frames/...`). **This is how kiro gets tested without any screen-scraping.**

### 8.2 Existing tests
`test_kiro_native_permissions.py` and `test_kiro_native_session_forwarder.py` die in Phase 4; `test_kiro_native_bridge.py` shrinks to profile tests; `test_kiro_spawn_env.py` / `test_acp_spawn_env.py` / `test_acp_cli_harnesses.py` extend. **`tests/e2e_ui/messages/test_kiro_concurrent_permissions.py` becomes the centrepiece** — it should assert three simultaneous requests each resolve to their own `id` regardless of arrival order (§12.5 shows kiro really does deliver them out of order).

### 8.3 New tests
Gap D regression (a policy rule for `shell` matches a kiro shell request); Gap E (three concurrent requests produce three *simultaneously open* cards); profile test (`--agent` name, `mcpServers`, `allowedTools`); protocol test (integer `1` still sent for all rows).

---

## 9. Risks — post-spike status

| # | Risk | Status |
|---|---|---|
| R1 | Protocol dialect mismatch | **REFUTED** (§12.1) |
| R2 | ACP mode may not stream | **REFUTED** — it streams (§12.2) |
| R3 | `allowedTools` may not pre-authorize in ACP | **CONFIRMED WORKING** (§12.3) |
| R4 | MCP may not load from profile | **CONFIRMED** (§12.3) |
| R5 | Reader loop serializes approvals | **CONFIRMED — real defect** (§12.5) |
| R6 | `WARM_REATTACH` → `COLD_ONLY` regression | **Still stands** — mitigated by keeping `kiro-native` |
| R7 | Mid-turn steering (`supports_live_message_queue`) may be lost | **Still unknown** — not tested |
| R12 | Human-facing bubbling not observed end-to-end for kiro | **PARTIAL** — kiro-specific half proven; generic `ctx.elicit()` hop verified by wiring inspection only (§12.6b) |
| R8 | `env_passthrough` limits for catalog rows | **Low** — kiro auths from disk (IAM Identity Center verified) |
| R9 | KiroCrew provenance | **Downgraded** — reference only, and its protocol claim was wrong |
| **R10** | **Tool name/args extraction breaks policy matching** | **NEW — CONFIRMED** (§12.4) |
| **R11** | **`_meta.trustOptions` (command-pattern scopes) lost** | **NEW — fidelity gap**, not a blocker (§12.4) |

---

## 10. Scope estimate — **Medium**

**Why not Small:** touches the spec layer, harness registry, spawn-env builder, and `AcpExtension` (shared by five harnesses). Gaps D and E are real code changes inside `acp_executor.py`, and D is security-relevant so it needs careful tests.

**Why not Large:** the hard part — a correct, policy-integrated, elicitation-bubbling ACP client — already exists and **is now proven to work against kiro-cli with zero modifications**. The kiro-specific surface is two narrow executor fixes plus one catalog row.

Rough shape: Phase 1 ≈ 1-2 days · Phase 2-3 ≈ 2-3 days · Phase 4 ≈ 1-2 days.

---

## 12. Phase 0 — results of the spike

**Method.** Zero-diff. Scratch workspace at `~/personal/galaxy-far-far-away/spike/ws` with one throwaway profile `.kiro/agents/omnigent-spike0.json` (mcpServers → a 90-line stub MCP server; `allowedTools: ["@spike/spike_free_tool"]`). No production agent, no omnigent repo file, and no `kiro-native-ui` was touched. Probes: `probe_handshake.py`, `probe_session.py`, `probe_concurrency.py`, `check_extract.py`, `run_executor.py`, `run_executor_concurrent.py`.

### 12.1 R1 — protocol version: **REFUTED**
Sent `"protocolVersion": 1` (exactly what `acp_executor.py:170` hardcodes):
```
--> {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,...}}
<-- {"jsonrpc":"2.0","result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true,
    "promptCapabilities":{"image":true,"audio":false,"embeddedContext":false},
    "mcpCapabilities":{"http":true,"sse":false},...},
    "agentInfo":{"name":"Kiro CLI Agent","title":"Kiro CLI Agent","version":"2.20.1"}},"id":1}
```
kiro-cli 2.20.1 **accepts and echoes integer `1`**. KiroCrew's `PROTOCOL_VERSION = "2025-08-22"` does not apply to this version. **The "top blocker" does not exist.** Bonus: `loadSession: true` (session resume is available) and `image: true`.

### 12.2 R2 — streaming deltas: **REFUTED (it streams)**
```
<-- {"method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"S"}}}}
<-- ... {"text":"PIKE_OK::"}}}}
<-- ... {"text":"spike_free_tool"}}}}
```
Update kinds observed: `{'tool_call': 1, 'tool_call_update': 1, 'agent_message_chunk': 3}`; a later turn produced 9 chunks. Through our own executor this surfaced as **`TextChunk` × 3** (§12.6). The `streaming=False` recorded for `kiro-native` is a TUI-path artifact; **the ACP row should declare `streaming=True`.**

### 12.3 R3 + R4 — `allowedTools` and MCP-from-profile: **BOTH CONFIRMED**
With `session/new` sent as `"mcpServers": []`, kiro still loaded the server from the `--agent` profile:
```
<-- {"method":"_kiro.dev/mcp/server_initialized","params":{"serverName":"spike",...}}
<-- session/new result: "modes":{"currentModeId":"omnigent-spike0",...}
```
The pre-authorized tool ran with **zero** permission requests:
```
<-- {"sessionUpdate":"tool_call_update","status":"completed","title":"Running: @spike/spike_free_tool",
     "rawOutput":{...:"SPIKE_OK::spike_free_tool"}}
SUMMARY: permission requests: 0
```
The non-listed tool raised one:
```
SUMMARY: permission requests: 1  - tool='Running: @spike/spike_gated_tool'
```
**R3 confirmed in ACP mode** (previously only known for TUI): `allowedTools` pre-authorization works, so `sys_session_*` orchestration will not spam cards. **R4 confirmed**: the profile is the MCP channel → the row must set `omnigent_mcp=False` and the profile writer must carry the relay.

### 12.4 R10 (NEW) — tool identity is lost: **CONFIRMED, security-relevant**
Real frame for the builtin shell tool:
```json
"toolCall":{"title":"Running: echo SPIKE_SHELL_MARKER",
            "rawInput":{"__tool_use_purpose":"...","command":"echo SPIKE_SHELL_MARKER"}},
"_meta":{"kiro":{"toolName":"shell"}}
```
Our own code, run against that frame verbatim (`check_extract.py`):
```
_extract_tool_call -> tool_name = 'Running: @spike/spike_gated_tool'
  would a rule for 'spike_gated_tool' match? False
_scoped_options    -> ['Yes', 'Always', 'No']                       ← GOOD
_permission_outcome(allow=True,  option_id=None) -> {'outcome':{'outcome':'selected','optionId':'allow_once'}}
_permission_outcome(allow=False, option_id=None) -> {'outcome':{'outcome':'selected','optionId':'reject_once'}}
```
`_extract_tool_call` prefers `title`, and kiro's title is a **human sentence that embeds the command** — it varies per invocation, so a static TOOL_CALL policy rule can *never* match it. A `DENY` rule for `shell` would silently fail to fire. The clean name is available at `_meta.kiro.toolName` (`"shell"`) / `_meta.mcpToolIdentity.toolName`. **This must be fixed before any agent is migrated.** Good news: arguments *are* present (`rawInput.command`), so argument-inspecting rules work once the name is right.

### 12.5 R5 (NEW severity) — concurrency: **CONFIRMED, real defect**
kiro fans out. Holding every request unanswered for 8 s:
```
[  6.93s] REQUEST #1 id=4860b323 title='Running: echo THREE'
[  6.93s] REQUEST #2 id=ad8566a1 title='Running: echo ONE'
[  6.93s] REQUEST #3 id=b1c0aabb title='Running: echo TWO'
gaps between requests: ['0.00s', '0.00s']
```
Three simultaneous requests — **and note the arrival order: THREE, ONE, TWO.** The scrambling seen today originates in **kiro-cli itself**, not our code. Under ACP that is harmless (each carries its own `id`); under positional keystrokes it is exactly the bug.

Our executor, however, serializes them (`acp_executor.py:1623`, whose own comment reads *"Blocks while the human decides"*). Holding each card 5 s:
```
[  5.51s] CARD OPENED  'Running: echo THREE'
[ 10.51s] CARD ANSWERED 'Running: echo THREE'
[ 10.51s] CARD OPENED  'Running: echo ONE'
[ 15.52s] CARD ANSWERED 'Running: echo ONE'
[ 15.52s] CARD OPENED  'Running: echo TWO'
```
Exactly one HOLD apart → **head-of-line blocking**: cards #2/#3 are not even created until #1 is answered, and `session/update` events stall meanwhile. Fix: dispatch `_respond_to_agent_request` as a tracked task — safe precisely because replies are `id`-addressed.

### 12.6 Item 3 — real approval through our own executor: **PASS**
Unmodified `AcpExecutor` + `kiro-cli acp --agent omnigent-spike0`, with a stub in the exact slot `ExecutorAdapter` fills with `ctx.elicit()`:
```
  [ToolCallRequest] 'Running: echo SPIKE_E2E_MARKER'
[policy] phase=PHASE_TOOL_CALL name='Running: echo SPIKE_E2E_MARKER' args={... 'command': 'echo SPIKE_E2E_MARKER'}
*** ELICITATION CARD RAISED (would bubble via ctx.elicit) ***
    buttons   : ['Yes', 'Always', 'No']
  [ToolCallComplete] ; [TurnComplete] response='SPIKE_E2E_MARKER'
event kinds: {'ToolCallRequest': 1, 'ToolCallComplete': 1, 'TextChunk': 3, 'TurnComplete': 1}
```
Reject path:
```
    answering : 'No'
  [TurnComplete] response="The shell command was denied, so `echo SPIKE_DENIED` did not run..."
```
The full chain — policy → elicitation → id-addressed reply → turn continues — works **with zero code changes**. Because that stub occupies the same slot `_stable_elicitation_choice_handler` fills, the remaining hop to a human is the generic `ctx.elicit()` bubbling already in production for claude-sdk.

### 12.6b Bubbling to a human — what is proven vs. what is NOT

**Proven live:** kiro's `session/request_permission` reaches
`_decide_permission` -> `_ask_user` -> `_elicitation_choice_handler(tool_name,
tool_input, options)` with kiro's real options, and the handler's return value
becomes an id-addressed reply kiro accepts.

**NOT observed live:** an actual human clicking an approval card for a
kiro-backed session. The spike filled the handler slot with a stub, because no
`acp`-harness agent pointing at kiro-cli exists (`sys_agent_list` ->
`local_configs: []`), and creating one would add a user-visible agent to the
picker — the production litter this spike was told to avoid.

**Why the residual risk is low, by code inspection** (`_executor_adapter.py`):
```python
if (hasattr(executor, "_elicitation_choice_handler")
        and executor._elicitation_choice_handler is None):
    executor._elicitation_choice_handler = self._stable_elicitation_choice_handler

async def _stable_elicitation_choice_handler(
    self, tool_name: str, tool_input: dict[str, Any], options: Sequence[str]
) -> str | None:        # ... ends in:  result = await ctx.elicit(elicitation_id, params)
```
`AcpExecutor` calls exactly that signature at `acp_executor.py:956`. The
assignment carries **no harness-name branch**, so the hop from the stub to a
real human is the generic `ctx.elicit()` path already in production for
claude-sdk, goose, qwen, devin, grok and jcode. The kiro-specific half is
proven; the remaining half is shared code with no kiro-specific behaviour.

**To close this fully** (recommended during Phase 2, when the `kiro` row makes
the agent legitimate rather than litter): register the row, launch a session,
ask it to run a non-pre-authorized shell command, and confirm the card renders
with `[Yes, Always, No]` and that answering it releases the turn.

### 12.7 R11 (NEW) — `_meta.trustOptions` fidelity gap
Kiro offers structured command-pattern scopes our generic path ignores:
```json
"_meta":{"trustOptions":[
  {"label":"Full command","display":"echo SPIKE_SHELL_MARKER","patterns":["echo SPIKE_SHELL_MARKER"]},
  {"label":"Partial command","display":"echo SPIKE_SHELL_MARKER *","patterns":["echo SPIKE_SHELL_MARKER( .*)?"]},
  {"label":"Base command","display":"echo *","patterns":["echo( .*)?"]}]}
```
These are the trust scopes `permissions.py` screen-scrapes today. `_scoped_options` reads only the standard `options`, so we would offer `Yes/Always/No` and lose "allow `echo *`". Not a blocker — a candidate for the vendor extension later.

### 12.8 Also observed (worth knowing)
- Vendor notifications our generic path ignores: `_kiro.dev/session/update` (carries `tool_call_chunk`), `_kiro.dev/metadata` (`contextUsagePercentage`, `turnDurationMs`), `_kiro.dev/commands/available`, and **`_kiro.dev/subagent/list_update`** — kiro has a sub-agent dialect, so `AcpExtension.subagent_sources` could later surface kiro sub-agents as child sessions (as Devin does).
- `session/new` returns `modes.currentModeId = "omnigent-spike0"`, a clean assertion that the profile was applied.

### 12.9 Cleanup
- `git -C ~/personal/omnigent status` → only the intentional `docs/kiro-native-acp-migration-plan.md` (untracked). The `result` file predates this session. **Nothing written to the repo's `.kiro/`.**
- No stray `kiro-cli acp` processes remain.
- Spike artifacts (`~/personal/galaxy-far-far-away/spike/`) were **deleted** at the end of the run, as instructed. They lived outside the repo and outside production. Every frame they produced is quoted verbatim in this section, and the probes are ~90 lines each to recreate if the Phase-1 fixture tests want them.
- Pre-existing, **not mine**: `~/.kiro/agents/__probe_test_agent__.json` (dated Sep 14, from an earlier investigation). Left untouched; Lucas may want to delete it.
- The three kiro chat sessions are persisted inside kiro's own `~/.local/share/kiro-cli/data.sqlite3`; they are ordinary local CLI sessions with no production effect.

---

## 13. Recommendation

**Proceed to implementation — with Gap D (tool identity) as a hard prerequisite.**

The spike retired the risk that would have killed the project (protocol dialect) and proved the end-to-end path works unmodified. It also upgraded the case for migrating: kiro fans out concurrent, out-of-order permission requests, which the TUI path can *never* handle safely, and the ACP path handles by construction.

But do **not** ship a bare catalog row. Gap D means a naive migration silently stops TOOL_CALL policy rules from matching kiro's tools — a security regression traded for a UX win. Land Gap D + Gap E first (both small, both inside `acp_executor.py`/`acp_extension.py`, both now covered by real captured frames), then the row, then per-agent opt-in.

---

## 14. Implementation round 1 — what shipped

Four additive commits on `custom-features`. **Nothing was removed or replaced:**
`kiro-native` and every agent on it (`kiro-native-ui`, `Work`, the five
specialists) are untouched.

| Hash | Concern |
|---|---|
| `d923fd451` | R10 — TOOL_CALL policy gates on the machine tool name |
| `4a5e13007` | R5 — concurrent permission requests no longer serialized |
| `4f9198b70` | `kiro-acp` catalog row + per-agent opt-in |
| `30a511b29` | MCP relay handed to kiro before it starts (option (a)) |

### 14.1 R10 — fixed for every ACP harness
`_extract_tool_call` preferred `toolCall.title`, which kiro decorates per
invocation (`"Running: echo hi"`), so a rule written for `shell` could never
match and a DENY silently failed to fire. The machine name is now resolved from
`_meta` via a table (`mcpToolIdentity.toolName`, `kiro.toolName`, Goose's two
shapes). kiro's permission frame omits the name for *builtin* tools, so the name
reported on the originating `tool_call` update is cached and used as fallback.
That cache is kept **separate from the display title**, so tool cards still read
the agent's humanized title and agents sending no `_meta` (Devin/Grok/jcode/
generic) resolve byte-identically to before.

### 14.2 R5 — fixed
Each server-initiated request now runs as its own tracked task; safe because
replies are `id`-addressed and `_send` already holds a write lock. Tasks are
cancelled on session reset. The regression test reproduces the captured fan-out
(three cards held open at once) and **was verified to fail on the old code**.

### 14.3 MCP delivery — option (a), verified live
kiro reads MCP servers once at startup from the `--agent` profile and ignores
`session/new.mcpServers`. The relay is now started and written into the profile
*before* `_start_process`. Both channels share one `_ensure_relay`, so a
profile-delivered agent gets the **same token-only bridge dir** — the relay
tools, not raw `sys_os_*`. `includeMcpJson` is set to `false` on these profiles
so a kiro-native session's broader workspace `mcp.json` cannot be merged in
behind it (option (b) was explicitly rejected on that security posture).

Live against kiro-cli 2.20.1: a `kiro-acp` agent called
`@omnigent/sys_session_list` on its **first** message, the relay dispatched it,
and no approval card was raised (`allowedTools` pre-authorization).

---

## 15. Final risk verdicts

| # | Risk | Verdict |
|---|---|---|
| R1 | Protocol dialect | **REFUTED** — integer `1` accepted and echoed |
| R2 | No streaming | **REFUTED** — `agent_message_chunk` deltas arrive |
| R3 | `allowedTools` in ACP | **CONFIRMED WORKING**, including via the relay |
| R4 | MCP from profile | **CONFIRMED** — and now wired (see 14.3) |
| R5 | Serialized approvals | **FIXED** (`4a5e13007`) |
| R10 | Tool identity lost | **FIXED** (`d923fd451`) |
| R11 | `_meta.trustOptions` fidelity | Open, not a blocker |
| **R7** | **Mid-turn steering** | **CONFIRMED LOST — real regression** (15.1) |
| **R12** | **Human-facing bubbling** | **PENDING a real coordinator test** (15.2) |

### 15.1 R7 — confirmed lost (regression for coordinators)
`AcpExecutor` overrides neither `supports_live_message_queue` nor
`enqueue_session_message`, so it inherits the base `Executor` defaults: `False`
and a no-op returning `False`. `KiroNativeExecutor` by contrast declares
`supports_live_message_queue() -> True` and injects the text into the live TUI.

So **mid-turn steering does not work on the ACP path**. This is a real
capability regression, and it matters most for exactly the agent most worth
migrating: a coordinator that a human steers while it works. Weigh this before
moving `Work`; a specialist that runs a task to completion loses little.

Closing it would mean implementing `enqueue_session_message` on `AcpExecutor` —
ACP has no standard mid-turn injection, so it likely needs `session/cancel`
plus a re-prompt carrying the queued text, which changes turn semantics. Not
attempted in this round.

### 15.2 R12 — parsing validated, bubbling still untested
Validated: an agent YAML declaring `harness: kiro-acp` parses, canonicalizes,
routes to `omnigent.inner.acp_harness`, and yields
`kiro-cli acp --agent omnigent-<digest>` plus the MCP profile path. Also
validated earlier: kiro's permission frame reaches `_decide_permission` ->
`_ask_user` -> the elicitation handler slot, and the handler's answer becomes an
`id`-addressed reply kiro accepts.

**Not validated: a human actually approving one.** The analysis agent has no
`sys_session_create` / `sys_session_send`, so it could not spawn a child session,
and a genuine "human clicks the card" test needs a person regardless. The
remaining hop is `ExecutorAdapter._stable_elicitation_choice_handler` ->
`ctx.elicit()`, which is generic, branch-free, and already in production for
claude-sdk / goose / qwen / devin / grok / jcode.

A scratch agent is parked for the coordinator to run this test:
`~/personal/omnigent/.omnigent/agent-configs/work-acp-spike.yaml` (gitignored,
so it is not repo litter). Ask it to run `echo hi` — not in `allowedTools`, so
it must raise a card offering **[Yes, Always, No]**.

**Prerequisite:** the running Omnigent server's harness registry predates these
commits (`sys_session_get_info` shows a `configured_harnesses` map with
`kiro-native` but no `kiro-acp`), so the runner/server must be restarted before
`harness: kiro-acp` resolves.

---

## 16. Unrelated finding — pre-existing test-isolation bug

Running `tests/inner/ tests/runtime/harnesses/` together yields **46 failures**
(mostly `tests/runtime/harnesses/test_executor_adapter_recovery.py`), while each
file passes alone and `tests/runtime/` alone is 1410 green.

**This is not caused by this work.** Reproduced identically in a clean worktree
at base commit `8c2ee33f0`, before any of the four commits above: 46 failed /
2790 passed there vs 46 failed / 2797 passed with the changes (the +7 is this
round's new tests).

Worth its own investigation: cross-test pollution of that size can mask real
regressions in CI, and it silently punishes anyone running a broad local suite.
Filed here only so it is not lost; out of scope for the migration.

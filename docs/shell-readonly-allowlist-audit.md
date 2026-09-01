# Read-only shell allowlist — audit and proposals (Phase 1)

**Status:** investigation / proposal for Phase 1 (below), superseded in part
by Phase 2 (implemented). See the update note immediately below before
reading §5–§6 as current guidance.

> **Update (Phase 2, implemented):** §5's and §6's verdict — "cannot be made
> safe in this matcher" — is still correct for the plain *prefix* matcher
> this document audited. It does not hold for a full-argv CEL guard added on
> top of that matcher: a guarded pattern entry evaluates a CEL expression
> against the command's ENTIRE real-invocation token list (not a fixed-length
> prefix), so `find`'s positionally-free predicates and `sed`'s
> options-after-operands no longer evade detection the way they did in every
> simulation below. `find`, `sed`, and `awk` are now guarded `core`-preset
> entries (`omnigent/policies/builtins/data/shell_readonly_presets.yaml` +
> `_compile_guard`/`_GUARD_FACT_EXTRACTORS` in `shell_readonly.py`) that ASK
> — never ALLOW — on any predicate/flag/script-text construct they
> recognize as dangerous, and ASK on anything their extraction can't
> classify (external script files, unparsed flags). This is a mitigation,
> not the elimination the "Unacceptable" verdict in §10 was written
> against: the enumeration of dangerous predicates/flags can still fall
> behind a variant not listed, and shell expansion (`$(...)`/`$VAR`) inside
> an argument is still outside static token inspection. See the
> implementing PR's "Coverage notes" for the full residual-risk statement.
> §9's `aws`/`aws-sso` findings are unrelated to this update and still
> stand as written — no `aws`/`aws-sso` change shipped with it.

This document (Phase 1) is otherwise unmodified from its original
investigation — no code had changed at the time it was written.

**Scope:** `allow_read_only_shell` in
`omnigent/policies/builtins/shell_readonly.py` and the shared parsing
primitives in `omnigent/policies/builtins/_shell.py`.

**Bottom line up front:** the preset is *correct*. The exclusions of
`find`/`sed`/`awk` are deliberate and defensible, and I do not recommend
relaxing them. The two real friction sources are (1) the working directory
and (2) global flags placed before a subcommand — and **both are solvable
today with configuration only, no patch to the fork.**

One finding needs to be read before anyone edits an agent YAML: allowlisting
`aws-sso exec … --` as a prefix — even pinned to a specific org, account and
role — grants **arbitrary command execution under AdministratorAccess**
(§9.1, verified by simulation). It is the most dangerous line someone could
add here, and it looks careful.

---

## 1. Briefing claims vs. code

| # | Claim in briefing | Verdict | Evidence |
|---|---|---|---|
| a | A global flag before the subcommand breaks prefix matching | **Confirmed** | `shell_readonly.py:139` `_matches_pattern` compares `tokens[1:len(pattern)]` positionally against the pattern tail. `git --no-pager log` → `tokens[1] == "--no-pager" != "log"` → no match → ASK. Verified by simulation: `kubectl --context prod get pods` → ASK, `kubectl get pods --context prod` → ALLOW. |
| b | `_has_unsafe_shell_syntax` rejects redirection *before* the allowlist is consulted | **Confirmed** | `shell_readonly.py:76` defines it; `shell_readonly.py:198` `_segment_is_safe` calls it at the top, before `shlex.split`, before `real_invocation_tokens`, before `_matches_pattern`. Any `>` or `<(` anywhere in the segment is an immediate `False`. |
| c | `find` / `sed` / `awk` / `cd` / `set` / `export` genuinely absent from the presets | **Confirmed** | See §5–§7; absent from `data/shell_readonly_presets.yaml` and excluded on purpose. |
| d | The agent cannot run `git status` in the repo without human approval | **Refuted as stated** | `git status` is in the `git` preset and ALLOWs. What fails is running it *against a different directory*, because the tool has no `cwd` argument and `cd` is not allowlisted. The problem is the working directory, not `git status`. |

---

## 2. How the matcher actually works (Q1)

Pipeline, in order, for one `sys_os_shell` `command` string:

1. **`_evaluate`** — `shell_readonly.py:244`. Abstains (`None`) unless the
   event is a `tool_call` whose tool name is in `SHELL_TOOLS`
   (`_shell.py:29`, six harness shell tools) and whose `command` argument is
   a non-empty string.
2. **`_evaluate_command`** — `shell_readonly.py:226`. Splits into segments
   and requires **every** segment to be safe. First failing segment produces
   the ASK reason.
3. **`split_command_segments`** — `_shell.py:184`. Pulls out `$(...)` and
   backtick bodies first (`_extract_command_substitutions`, `_shell.py:133`)
   and appends them as *their own segments*, then splits the residue on
   `&&`, `||`, `;`, `|`, a lone `&`, and newlines.
4. **`_segment_is_safe`** — `shell_readonly.py:198`, per segment:
   - depth guard `MAX_SHELL_NESTING = 4` (`_shell.py:130`) → `False`;
   - `_has_unsafe_shell_syntax` (`:76`) → `False` on `>` or `<(`;
   - `shlex.split`; a `ValueError` (unbalanced quotes) → `False`;
   - `real_invocation_tokens` (`_shell.py:218`) strips leading
     `VAR=value` assignments, `CMD_WRAPPERS` (`nohup`), and `_FLAG_WRAPPERS`
     (`timeout`, `nice`, `stdbuf`, `setsid`, `sudo`, `env`, `command`,
     `time`, `exec`) together with their own option flags and, for
     `timeout`, its duration positional;
   - `is_unresolved_invocation` (`_shell.py:263`) → `False` if the head
     still starts with `-` (an unmodelled wrapper flag);
   - `unwrap_shell_command` (`_shell.py:361`) recurses into `sh/bash/zsh/
     dash/ksh -c`, `eval`, and `env -S`;
   - finally `any(_matches_pattern(tokens, p) for p in patterns)`.
5. **`_matches_pattern`** — `shell_readonly.py:139`. Head compared by
   **basename** (`/usr/bin/git` ≡ `git`); remaining pattern tokens compared
   **literally and positionally**. Pure prefix match.

### The GHSA citation

`GHSA-7mqg-cx4g-x2rf` is cited twice in `_shell.py`:

- **`_shell.py:51`**, on `_FLAG_WRAPPERS` — defends against wrappers that
  carry their *own* flags. Skipping only the wrapper word would leave a flag
  as the apparent command, so `sudo -u root git push` would present as `-u`
  and slip the gate. `is_unresolved_invocation` (`:263`) is the explicit
  backstop for this enumeration falling behind a new wrapper.
- **`_shell.py:141`**, on `_extract_command_substitutions` — defends against
  a command hidden inside a substitution: `x=$(git push <url>)` looks like a
  bare env-assignment that `real_invocation_tokens` would skip, while the
  shell actually runs the push.

Read together: this parser was written by someone modelling an adversary who
controls the command string. That framing should govern every proposed
relaxation below.

---

## 3. The design cannot deny an argument (Q2)

`_matches_pattern` (`shell_readonly.py:139`) inspects only
`tokens[0:len(pattern)]`. **Everything after the pattern is unexamined.** A
pattern is a prefix grant over an unbounded argument tail.

Confirmed by simulation against the real policy:

- `extra_allow=[["git", "-C"]]` → `git -C <repo> status` ALLOW, and also
  **`git -C <repo> push origin main` ALLOW**, and **`git -C /etc reset
  --hard` ALLOW**. The "loose" form grants writes and reaches any repo on
  disk. **Do not use it.**
- `extra_allow=[["git","-C",<repo>,"status"], [...,"diff"], [...,"log"]]`
  (full literal) → `status` ALLOW, `log --oneline` ALLOW, `push origin main`
  ASK, `git -C /etc status` ASK. Safe, and works **today with no patch**.

Consequence for the central question: a hypothetical `[find]` pattern would
match `find / -exec rm -rf {} ;` — the tokens `find` matches, the rest is
never looked at. **This is the single most important property of the
design, and it is why `find`/`sed`/`awk` cannot simply be added.**

The prefix rule is a *safety* property, not a bug: it means a pattern can
only ever be made safe by making it *longer and more literal*, never by
adding exceptions. Any proposal that requires "allow X except when argument
Y appears" is asking for a matcher this policy does not have.

---

## 4. What is already possible today, with YAML only

Everything in this section needs **no patch to the fork** — only
`factory_params` in the agent YAML.

| Need | YAML-only solution | Why it works |
|---|---|---|
| `git status`/`diff`/`log` in a *specific* repo | `extra_allow` with the **full literal** `[git, -C, /home/lces/personal/omnigent, status]` (one entry per verb) | The prefix pins the repo path *and* the verb; `push` is not a listed verb, `/etc` is not the listed path |
| Global flag friction (`kubectl --context`, `aws --profile`) | Instruct the agent to put the flag **after** the subcommand | The pattern is a prefix; anything after it is unexamined (§3). `kubectl get pods --context prod` ALLOW vs `kubectl --context prod get pods` ASK |
| Extra read-only verbs of an already-present binary (`git blame`, `kubectl top`) | `extra_allow: [[git, blame], [kubectl, top]]` | Same matcher as the bundled presets |
| A whole new binary family (`aws`) | `extra_allow`, verb by verb (§9) | No preset needed; presets and `extra_allow` are merged into one pattern list (`shell_readonly.py:186-192`) |

What is **not** achievable with YAML alone: denying an argument (§3),
allowing redirection (§7), and making `cd` stick (§6/A).

**Rule for writing `extra_allow`:** a pattern is a *prefix grant over an
unbounded tail*. Write the longest literal prefix that still expresses what
you want. Never stop the pattern at a token that is followed by a
free-form operand (`[git, -C]`, `[kubectl, exec]`, `[aws, s3]` are all
dangerous for this reason).

---

## 5. `find` (Q3)

**Verdict: `find` cannot be made safe in this matcher. Do not add it, in the
preset or via `extra_allow`.**

### Write / execute vectors in GNU find

| Predicate | Effect |
|---|---|
| `-exec CMD ;` / `-exec CMD +` | Runs an arbitrary command per match / batched |
| `-execdir CMD ;` / `-execdir CMD +` | Same, with cwd set to the match's directory |
| `-ok CMD ;` / `-okdir CMD ;` | Same, gated on a stdin confirmation the agent can supply |
| `-delete` | Unlinks every match (implies `-depth`, deletes directories) |
| `-fprintf FILE FMT` | Writes arbitrary formatted content to an arbitrary path |
| `-fprint FILE` / `-fprint0 FILE` | Writes the match list to an arbitrary path |
| `-fls FILE` | Writes `ls -dils` output to an arbitrary path |

The `-f*` family is the important one: it is a **file write with no shell
redirection**, so `_has_unsafe_shell_syntax` (`shell_readonly.py:76`) never
sees a `>` and never fires.

### Simulated against the real policy

With `extra_allow=[["find"]]`, every one of these returns **ALLOW**:

```
find . -name foo                 ALLOW
find / -exec rm -rf {} +         ALLOW
find . -delete                   ALLOW
find . -fprintf /tmp/x %p        ALLOW
find . -execdir touch pwned +    ALLOW
find . -fls /tmp/out             ALLOW
```

### A longer literal prefix does not rescue it

This is the finding that closes the question. With
`extra_allow=[["find", ".", "-name"]]`:

```
find . -name x -delete           ALLOW
find . -name x -exec rm {} +     ALLOW
```

Because the pattern is a prefix and the tail is unexamined (§3), and because
`find` accepts dangerous predicates *anywhere after* the starting points,
there is **no prefix of a `find` command that constrains what follows**.
The trick that makes `git -C <repo> status` safe — pinning the verb at a
fixed position — has no analogue in `find`, whose "verbs" are positionally
free.

### Why an argument denylist would also be fragile

If someone proposed scanning the tail for `-exec`/`-delete`/`-fprintf`:

1. **The matcher has no argument inspection at all.** This is new code in
   the security-critical path, not a config change.
2. **Equivalent forms multiply.** Seven-plus predicates above, plus
   `-exec`/`-execdir`/`-ok`/`-okdir` variants and the three `-f*` writers;
   BSD/macOS `find` differs again. An enumeration that must be complete to
   be sound is the same shape as `_FLAG_WRAPPERS` — and that one needed
   `is_unresolved_invocation` (`_shell.py:263`) as an explicit backstop for
   falling behind.
3. **Shell expansion defeats literal scanning.** The policy sees the token
   `$F`, bash runs `-delete`. `split_command_segments` extracts `$(...)`
   and backtick bodies (`_shell.py:133`) precisely because the parser cannot
   see through expansion — but a bare `$F` parameter expansion is not
   extractable, since its value does not exist until runtime. A denylist
   over literal tokens is blind to it, while the current *allowlist* is not:
   an unknown token simply fails to match a literal pattern.

That asymmetry is the whole argument. **Allowlisting fails closed under
expansion; denylisting fails open.** Adding a denylist would move `find`
from the safe side of that asymmetry to the unsafe side.

### What to do instead

`grep` is already in the `core` preset, and the harness's own read tools
(`sys_os_read`) bypass the shell policy entirely. Almost every agent use of
`find` is "locate files by name", which `grep -rl` or the read tools cover
without granting an exec primitive.

## 6. `sed` and `awk` (Q4)

**Verdict: same as `find` — neither can be made safe here. The exclusions
are correct.** They fail for a reason worth stating separately, though.

### `sed`

Write / execute vectors:

- `-i` / `--in-place` (and `-i.bak`) — rewrites files in place.
- The `w FILE` command and the `s///w FILE` flag — writes to an arbitrary
  path from inside the *script operand*, with no shell redirection.
- `s///e` (GNU) — executes the pattern space as a shell command.
- `e COMMAND` (GNU) — executes a command directly.

Simulated with `extra_allow=[["sed"]]`: `sed -i.bak s/a/b/ f`,
`sed --in-place s/a/b/ f` and `sed s/a/b/w=out f` all **ALLOW**.

The killer is the same as for `find`, and worse: **GNU `sed` accepts options
after the operands**, so even a fully literal pattern is a wildcard.
Simulated with `extra_allow=[["sed", "-n", "1p", "f"]]`:

```
sed -n 1p f -i.bak s/a/b/ g      ALLOW      # rewrites g
```

A pattern that names the entire intended command *still* grants in-place
edits of any other file. There is no safe `sed` entry.

### `awk`

Write / execute vectors:

- `system("...")` — arbitrary command execution from the program text.
- `print > "file"` / `printf ... > "file"` — file write from the program.
- `print | "sh"` — pipes into a shell.
- `ENVIRON`/`getline` from a command: `"cmd" | getline`.

Two of these are accidentally caught by the existing defences, which is
instructive but not sufficient:

- `print > "file"` contains `>`, so `_has_unsafe_shell_syntax`
  (`shell_readonly.py:76`, called first in `_segment_is_safe` at `:198`)
  rejects the segment before any matching happens.
- `print | "sh"` contains `|`, so `split_command_segments`
  (`_shell.py:184`) splits it and the fragment fails to match.

But `system(...)` needs **no shell metacharacter at all**. Simulated with
`extra_allow=[["awk"]]`: `awk BEGIN{system(id)} f` → **ALLOW**. And with the
literal `extra_allow=[["awk", "-f", "p.awk"]]`,
`awk -f p.awk BEGIN{system(id)} f` → **ALLOW**.

So the two accidental catches create a *false sense* of coverage: they
handle the noisy forms and miss the quiet one. Do not treat them as a
reason to relax.

### Case-by-case summary

| Binary | Safe to add to preset? | Safe via literal `extra_allow`? | Why |
|---|---|---|---|
| `find` | No | **No** | Predicates are positionally free; tail unexamined |
| `sed` | No | **No** | Options accepted after operands; `w`/`e` write and exec from the script operand |
| `awk` | No | **No** | Program text is an operand; `system()` needs no metacharacter |
| `cd` | No | No — and pointless | Effect does not persist (§7, finding A) |
| `set` / `export` | No | No — and pointless | Same: new process per call |

## 7. Global flags (Q5), cwd (Q6), redirection (Q7)

### 7.1 Global flags before the subcommand (Q5)

Simulated against the real policy with `presets: [core, git, k8s]`:

```
git status                                        ALLOW
git --no-pager log                                ASK
git -c protocol.ext.allow=always status           ASK
git -C /etc status                                ASK
kubectl get pods --context prod                   ALLOW
kubectl --kubeconfig /tmp/evil.yaml get pods      ASK
```

The friction is real, but **the same mechanism that blocks `--no-pager` is
what blocks `-c` and `--kubeconfig`.** They are not separable by a generic
rule.

**Why "skip any token starting with `-`" is unsafe.** The skipped tokens are
exactly where the arbitrary-code-execution primitives live:

- `git -c diff.external=<cmd> diff` runs `<cmd>`. So does
  `-c core.pager=<cmd>`, `-c core.sshCommand=<cmd>`,
  `-c uploadpack.packObjectsHook=<cmd>`. `-c protocol.ext.allow=always`
  re-enables the `ext::` transport. Every one of these turns an *allowlisted
  read verb* (`git diff`, `git log`) into command execution.
- `kubectl --kubeconfig <file>` is equally bad: a kubeconfig may contain an
  `exec` credential plugin, so pointing it at an agent-written file executes
  an arbitrary binary during `kubectl get pods`. `--server`, `--token` and
  `--as` (impersonation) are their own problems.
- `aws --endpoint-url <host>` redirects credentialed calls to an
  attacker-chosen endpoint; `--profile` can select a profile whose
  `credential_process` runs a command.

Two further reasons not to generalise:

1. **It would walk back the GHSA fix at the parser level.** The whole point
   of `is_unresolved_invocation` (`_shell.py:263`) is that a leading `-`
   must *not* be treated as "harmless, keep looking" — that assumption is
   what let `sudo -u root git push` through. Reintroducing it in the matcher
   restores the same class of bug one layer up.
2. **Value arity has to be modelled per flag.** Skipping `-c` but not its
   value leaves `protocol.ext.allow=always` as the apparent subcommand, so
   it fails closed — but any implementation that also skips values inherits
   the whole `_FLAG_WRAPPERS` enumeration burden (`_shell.py:63-101`), now
   multiplied per gated binary.

**If it is ever implemented**, the only defensible shape is a *per-binary
allowlist of specific global flags with declared arity* — e.g. `git:
--no-pager (0 values), --paginate (0)`; `kubectl: --context (1)` — with an
explicit denylist for `git -c`/`--config-env`, `kubectl --kubeconfig/
--server/--token/--as`, and `aws --endpoint-url/--ca-bundle/--no-verify-ssl`.
Note that even `git -C <path>` is not inert: it grants read access to *any*
repo on disk, so it should take a configured path list rather than a free
operand.

**Recommended for now: don't.** The zero-code workaround is to place the
flag *after* the subcommand (`kubectl get pods --context prod`,
`aws s3 ls --profile cogna`), which both CLIs accept and which the prefix
matcher allows today.

### 7.2 The working directory (Q6)

`cd` is genuinely useless here, not merely blocked. Every `shell` op spawns
a **new process**:

- `omnigent/inner/os_env.py:1053` — the `op == "shell"` handler calls
  `_shell_impl(command=..., cwd=cwd, ...)`.
- `os_env.py:1453` builds `argv = _shell_argv(...)`, which is
  `[bash, "--noprofile", "--norc", "-c", command]` (`os_env.py:1534`).
- `os_env.py:1455-1462` runs `subprocess.run(argv, cwd=str(cwd),
  env=_child_shell_env(), ...)`.
- That `cwd` comes from the helper's config (`os_env.py:367`, `:989`) and is
  **never rewritten by the result of a command**.

The long-lived `subprocess.Popen` at `os_env.py:594`
(`_HelperProcessClient._start_locked`, reused at `:444`) is the JSON-RPC
helper process, **not** a persistent shell. Each `shell` op still forks its
own `bash -c`.

| Option | Verdict |
|---|---|
| (i) add a `cwd` argument to the shell tool | Possible, but **only together with a policy change** — see the trap below |
| (ii) allowlist `cd` | **Dead.** `cd` in one `bash -c` cannot affect the next. Spending a human approval on it buys literally nothing |
| (iii) solve via global-flag skipping (§7.1) | Only helps binaries that have a `-C`-style flag (`git`, `make`, `tar`); needs the risky code of §7.1 |
| (iv) literal `extra_allow` prefixes | **Recommended.** Zero code, works today, safe (§4, §8) |

**The trap in option (i):** `_evaluate` reads only `args["command"]`
(`shell_readonly.py:255-262`). If a `cwd` argument were added to the tool
and the policy left untouched, every existing grant would silently widen
from one directory to the entire filesystem — `git status` with
`cwd=/some/other/repo` would ALLOW, and the repo pinning of §4 would
evaporate. If (i) is ever built, it must ship *in the same change* as an
allowed-cwd parameter on this policy. **Never (i) alone.**

Trade-off of the recommended (iv): safety and zero code, paid for with
verbosity — one `extra_allow` entry per (repo × verb), listing absolute
paths that must be updated when repos move.

### 7.3 Redirection (Q7)

`_has_unsafe_shell_syntax` (`shell_readonly.py:76-95`) is a substring test —
`">" in segment or "<(" in segment` — and `_segment_is_safe` (`:198-201`)
calls it **first**, before `shlex.split`, before wrapper stripping, before
any pattern match. So:

- Any `>` anywhere disqualifies the segment, including inside a quoted
  argument (`grep "a > b" f` → ASK). The docstring (`:86-90`) states this is
  intentional: "a false positive only costs an extra ASK, it never produces
  a silent ALLOW."
- Input redirection is *not* caught (verified: `cat f 2</dev/null` →
  ALLOW). That is consistent, not an oversight: `<` cannot write, and
  reading a file is already what the allowlisted commands do.

**Is it worth distinguishing `2>/dev/null` from `> file`? No.**

- *Cost:* doing it correctly means tokenizing redirections with quote
  awareness and classifying targets across `>`, `>>`, `>|`, `&>`, `2>`,
  `2>&1`, `1>&2`, `N>&M` — in the security-critical path, where a parser
  bug is a silent ALLOW of a file write.
- *Benefit: near zero in this harness.* The op result already returns
  `stdout` and `stderr` as **separate fields** (`os_env.py:1449-1451`), so
  suppressing stderr gains the agent nothing it cannot get by ignoring the
  field.

**Recommendation: do not touch the redirection check. Instruct the agents
instead** — "never redirect; stderr is returned separately; if you need
output in a file, use the write tool." This is the cheapest correct answer
in the whole audit.

## 8. `extra_allow` plumbing and a concrete YAML block (Q8)

### The params really do reach the factory

1. `omnigent/inner/loader.py:528` `_parse_policy` reads one entry of the
   agent YAML `policies:` mapping.
2. `:543` resolves `handler:` (legacy alias `callable:`) to the callable.
3. `:547-552` — when `factory_params` is present, it calls
   `callable_obj(**factory_params)`; `:553-558` raises if the factory does
   not return a callable.
4. `:559-570` stores the built evaluator on `FunctionPolicy` together with
   `factory_params`/`factory` (kept for re-building server-side).
5. Server/agent-plane route: `_translate_function_policy_yaml`
   (`omnigent/spec/omnigent.py:760-826`) rewrites `handler` +
   `factory_params` into `function: {path: <shim>, arguments: {...}}`, and
   `omnigent/runtime/policies/builder.py:1532` passes
   `arguments=policy.factory_params` into the build.

So `presets` and `extra_allow` are ordinary keyword arguments of
`allow_read_only_shell` and are honoured from YAML on both routes.
Validation differs by route, and this matters:

- **Server/API route** (`POST` session or default policies):
  `validate_factory_params` (`omnigent/policies/registry.py:244`) checks the
  params against `params_schema` (`shell_readonly.py:289`) — called at
  `server/routes/session_policies.py:196` and
  `server/routes/default_policies.py:209`.
- **YAML loader route**: no schema check. A misspelled *key* still fails
  loudly (`TypeError: unexpected keyword argument` from
  `callable_obj(**factory_params)`, `loader.py:552`), but a misspelled
  **preset name is silently ignored** — `all_presets.get(name, [])`
  (`shell_readonly.py:190`) returns an empty list. A YAML typo like
  `presets: [kubernetes]` therefore yields a policy that ASKs for
  everything, with no error. Worth knowing when debugging "why is it still
  asking".

### Concrete, safe block

```yaml
policies:
  allow_safe_shell:
    type: function
    handler: omnigent.policies.builtins.shell_readonly.allow_read_only_shell
    factory_params:
      presets: [core, git, python, k8s, terraform]
      extra_allow:
        # Repo-pinned git: path AND verb are both literal.
        - [git, -C, /home/lces/personal/omnigent, status]
        - [git, -C, /home/lces/personal/omnigent, diff]
        - [git, -C, /home/lces/personal/omnigent, log]
        - [git, -C, /home/lces/personal/omnigent, show]
        # Read-only verbs missing from the bundled git preset.
        - [git, blame]
        - [git, rev-parse]
        # AWS, verb by verb (see §9). Never [aws, s3] alone.
        - [aws, sts, get-caller-identity]
        - [aws, s3, ls]
        - [aws, ec2, describe-instances]
```

**Do not write** `extra_allow: [[git, -C]]`. Simulated against the real
policy, that grants `git -C <anything> push origin main` and
`git -C /etc reset --hard` (§3). The literal form above was simulated too:
`push`/`reset` and any other repo path fall through to ASK.

Also avoid `[git, -c]` (lowercase) in any form — see §7/§5 on
`git -c protocol.ext.allow=always`.

## 9. An `aws` preset (Q9)

There is no `aws` preset today — the enum is `core, git, node, python,
rust, docker, k8s, nix, terraform` (`shell_readonly.py:296-306`).

### 9.1 The blocker: the real workflow is `aws-sso exec`, not `aws`

Per `~/.claude/skills/aws/references/aws-sso.md:51-71`, AWS commands are run as:

```
aws-sso exec [--sso <Org>] -A <AccountId> -R <RoleName> -- <command>
```

Two consequences, both verified by simulation:

1. **An `aws` preset would be inert for this workflow.** The head token is
   `aws-sso`, which no pattern matches, so
   `aws-sso exec --profile x -- aws s3 ls` → **ASK** even with
   `[aws, s3, ls]` allowed. Building the preset without addressing this
   solves nothing for Lucas.
2. **Allowlisting `aws-sso exec` in any form is catastrophic.** It is a
   command *wrapper* — like `sudo` — that `_shell.py` does not model, so
   everything after `--` is the unexamined tail of §3. With the *fully
   literal, org/account/role-pinned* pattern
   `[aws-sso, exec, --sso, Somos, -A, 591981467796, -R, AWS-CloudAdmin, --]`:

   ```
   ... -- aws s3 ls                        ALLOW
   ... -- rm -rf /tmp/x                    ALLOW
   ... -- aws s3 rm s3://bucket --recursive  ALLOW
   ```

   That is **arbitrary command execution carrying AdministratorAccess
   credentials**, auto-approved. This is the single most dangerous entry
   anyone could add to `extra_allow`, and it looks responsible because it
   names a specific account and role. **Never write it.**

### 9.2 The two honest options

**(A) Config-only, today.** Pin the *entire* invocation, including the inner
command, so the tail is only the inner verb's arguments:

```yaml
- [aws-sso, exec, --sso, Somos, -A, "591981467796", -R, AWS-CloudAdmin, --, aws, s3, ls]
- [aws-sso, exec, --sso, Somos, -A, "591981467796", -R, AWS-CloudAdmin, --, aws, sts, get-caller-identity]
```

Safe, zero code. Cost: the entry count is
*orgs × accounts × roles × verbs* — it does not scale past a handful of
routinely used triples. (Quote the account id so YAML keeps it a string.)

**(B) Small patch: teach the parser that `aws-sso exec` is a wrapper.**
Add `aws-sso exec` handling to `_shell.py` so the real command *after the
first `--`* is re-parsed and matched normally, exactly as
`unwrap_shell_command` (`_shell.py:361`) already does for `bash -c` and
`env -S`. The `--` terminator makes this unusually safe to implement: no
flag-arity table is needed (unlike `_FLAG_WRAPPERS`), and **no `--` means no
unwrap, which falls through to ASK** — fail-closed by construction. Then a
normal `aws` preset works for both bare `aws` and `aws-sso exec -- aws`.

Risk of (B): after unwrapping, the account/role are no longer examined, so
the grant becomes "these verbs in **any** account and role the SSO session
can reach, including `AdministratorAccess`". This is acceptable *only*
because the verb list is strictly read-only — an admin role running
`describe-instances` is still just a read. It must be a conscious decision,
not a side effect. If per-account restriction is ever required, that is
argument matching, which this policy does not have (§3).

### 9.3 Proposed verb list — audited one at a time

No globs. No `aws * get-*`. Each line is a literal token list.

**Identity / cheap sanity checks**

| Pattern | Why safe |
|---|---|
| `[aws, sts, get-caller-identity]` | Returns the current identity; no mutation |

| Group | Patterns | Note |
|---|---|---|
| S3 | `[aws, s3, ls]`, `[aws, s3api, list-buckets]`, `[aws, s3api, get-bucket-location]`, `[aws, s3api, list-objects-v2]`, `[aws, s3api, head-bucket]` | `ls` only — the `s3` family also holds `cp`/`mv`/`rm`/`sync`, which is exactly why the verb must be pinned |
| EC2 / ELB | `[aws, ec2, describe-instances]`, `[aws, ec2, describe-security-groups]`, `[aws, ec2, describe-vpcs]`, `[aws, ec2, describe-subnets]`, `[aws, elbv2, describe-load-balancers]`, `[aws, elbv2, describe-target-groups]`, `[aws, elbv2, describe-target-health]` | Pure reads |
| EKS / ECS | `[aws, eks, list-clusters]`, `[aws, eks, describe-cluster]`, `[aws, eks, list-nodegroups]`, `[aws, ecs, list-clusters]`, `[aws, ecs, list-services]`, `[aws, ecs, describe-services]` | Pure reads. **`eks update-kubeconfig` excluded** — it writes `~/.kube/config` |
| RDS | `[aws, rds, describe-db-instances]`, `[aws, rds, describe-db-clusters]` | Pure reads |
| Logs / stacks | `[aws, logs, describe-log-groups]`, `[aws, logs, filter-log-events]`, `[aws, cloudformation, describe-stacks]`, `[aws, cloudformation, list-stacks]` | Reads. `logs tail --follow` deliberately omitted: read-only but long-running, it would hang the tool until timeout |
| IAM | `[aws, iam, get-user]`, `[aws, iam, list-roles]`, `[aws, iam, get-role]`, `[aws, iam, list-attached-role-policies]` | Read-only but discloses the permission graph — enable deliberately |

### 9.4 Explicitly excluded, with reasons

| Excluded | Reason |
|---|---|
| `aws ssm start-session` | Interactive shell into an instance — arbitrary code execution |
| `aws ecs execute-command` | Command execution inside a container |
| `aws lambda invoke` | Executes code **and** writes the output file |
| `aws secretsmanager get-secret-value` | Exfiltrates secrets into the transcript |
| `aws ssm get-parameter` / `get-parameters` | Same, via `--with-decryption` on SecureString |
| `aws kms decrypt` | Same |
| `aws configure get` / `set` | Reads credentials / writes config |
| `aws eks update-kubeconfig` | Writes `~/.kube/config`, changing what a later `kubectl` targets |
| `aws sts assume-role` | Mints credentials for another role — privilege pivot, and hard to audit after the fact |
| `aws s3 cp` / `mv` / `rm` / `sync`, all `s3api put-*` / `delete-*` | Mutation |
| `aws ce get-cost-and-usage` | Read-only, but **each call is billed** (~$0.01). Excluded as a cost surprise, not a security risk — enable knowingly |

### 9.5 Residual risk to accept explicitly

The tail after a matched prefix is unexamined (§3), so **`--profile`,
`--region` and `--endpoint-url` cannot be constrained**. Verified:
`aws s3 ls --endpoint-url http://evil` → ALLOW under `[aws, s3, ls]`.
The practical impact is limited — SigV4 signs the target host, so a
signature sent to a foreign endpoint is not replayable against real AWS, and
a read verb carries no payload to exfiltrate — but it does mean an `aws`
grant is a grant *in every account the session can reach*, at whatever
region and endpoint the agent chooses. Accept it consciously or do not grant
`aws` at all; there is no third option without an argument matcher.

---

## 10. Change inventory — risk, effort, code vs. configuration

| # | Change | Code or config? | Effort | Risk | Verdict |
|---|---|---|---|---|---|
| 1 | Repo-pinned `git -C <path> <verb>` literals in `extra_allow` | **Config** | Minutes | **Low** — verb and path both pinned; `push`/`reset`/other repos still ASK | **Do it** |
| 2 | Instruct agents: global flags *after* the subcommand | **Config** (prompt) | Minutes | **None** — changes no policy code | **Do it** |
| 3 | Instruct agents: never redirect; stderr comes back as its own field | **Config** (prompt) | Minutes | **None** | **Do it** |
| 4 | Extra read-only verbs for binaries already present (`git blame`, `git rev-parse`, `kubectl top`) | **Config** | Minutes | **Low** | Do it as needed |
| 5 | Fully-pinned `aws-sso exec … -- aws <verb>` literals for a few hot triples | **Config** | ~1h | **Low** *if* the inner verb is included in the pattern; **critical** if it stops at `--` (§9.1) | Do it, carefully |
| 6 | Teach `_shell.py` that `aws-sso exec … --` is a wrapper and re-parse the inner command | **Code** | ~half day + tests | **Medium** — fail-closed by design (no `--` → no unwrap → ASK), but it is new logic in the parser that the GHSA hardened | Do it if #5 gets unwieldy |
| 7 | Add an `aws` preset with the §9.3 verbs | **Code** (data file + enum) | ~half day | **Low-medium** — data only, but each verb is a standing grant across every reachable account | Do after #6; pointless before it |
| 8 | Per-binary global-flag skipping with declared arity (§7.1) | **Code** | ~1 day + tests | **Medium-high** — touches the exact assumption the GHSA fix hardened | Only if #2 proves insufficient |
| 9 | `cwd` argument on the shell tool **plus** an allowed-cwd policy parameter | **Code** (tool + policy, same change) | ~1 day | **High if split** — the tool change alone silently widens every existing grant to the whole filesystem (§7.2) | Defer; #1 covers the real need |
| 10 | Allow `find` / `sed` / `awk`, in any form | — | — | **Unacceptable** | **No** (§5, §6) |
| 11 | Allow `cd` / `set` / `export` | — | — | No security gain, no functional gain | **No** — it is a no-op (§7.2) |
| 12 | Relax the redirection check to permit `2>/dev/null` | **Code** | ~half day | **Medium** for ~zero benefit | **No** (§7.3) |

## 11. Recommended order

1. **#1, #2, #3 — configuration only, today.** This removes the great
   majority of the approval fatigue: repo-scoped git reads stop asking, and
   the two habits (flags after the subcommand, no redirection) eliminate the
   most common spurious ASKs. No attack surface changes at all.
2. **#5 — pin the handful of AWS invocations actually used.** Start with
   `sts get-caller-identity` and `s3 ls` on the one or two accounts touched
   daily. Measure how painful the entry count really is before writing code.
3. **#6 + #7 — the `aws-sso` unwrap plus the `aws` preset**, if and only if
   step 2 becomes unmanageable. Do them together: the preset is inert
   without the unwrap (§9.1).
4. **#8, #9 — only on demonstrated need**, and #9 only as a single change
   that includes the policy-side cwd parameter.

Everything in steps 1 and 2 is `extra_allow` in the agent YAML. Nothing
before step 3 requires a patch to the fork.

## 12. What I do **not** recommend relaxing

- **`find`, `sed`, `awk` — not in the preset, and not via `extra_allow`
  either.** Not because they are unusual, but because *no prefix of them
  constrains what follows*: `find`'s predicates are positionally free, `sed`
  accepts options after its operands, and `awk`'s program text is an
  operand. Verified: even fully literal patterns allowed `-delete`,
  `-i.bak`, and `system()` (§5, §6). Each is a general-purpose exec/write
  primitive wearing a text-processing costume. `grep` plus the harness read
  tools cover the legitimate uses.
- **`aws-sso exec` as a prefix grant — under any account/role pinning.**
  Verified to allow `-- rm -rf /tmp/x` with AdministratorAccess credentials
  (§9.1). If AWS is auto-allowed, either the inner command is part of the
  pattern (#5) or the parser is taught to unwrap it (#6). There is no third
  form.
- **Generic "skip leading `-` tokens" for global flags.** `git -c
  diff.external=<cmd>`, `kubectl --kubeconfig <file>` (exec credential
  plugins) and `aws --endpoint-url` are all arbitrary-code or
  data-redirection primitives hiding in the flag position, and the
  heuristic re-introduces exactly the assumption
  `is_unresolved_invocation` (`_shell.py:263`) was written to kill (§7.1).
- **The redirection check.** A substring test for `>` is crude and produces
  false ASKs, but it is checked before tokenisation and cannot produce a
  silent ALLOW. The benefit of refining it is a cosmetic `2>/dev/null` that
  this harness does not even need, since stderr is returned separately
  (§7.3).
- **A `cwd` tool argument without a matching policy parameter.** It would
  turn every directory-pinned grant into a filesystem-wide one, silently,
  with no diff in the policy config to review (§7.2).

## 13. Conclusion

The honest summary is the one the briefing anticipated: **the preset is
right; the friction is the working directory and the global flags.** The
`find`/`sed`/`awk` exclusions are not conservatism, they are the only
correct answer for a prefix matcher, and the code says so in its own
comments (`data/shell_readonly_presets.yaml:11-13`). The working-directory
problem is solved today by literal `extra_allow` prefixes, and the
global-flag problem by moving the flag after the subcommand. The only
change that genuinely needs code is the `aws-sso exec` unwrap — and only
because Lucas's AWS workflow puts a command wrapper in front of every
invocation.

---

### Footnote: simulating this policy locally

Run the interpreter directly, with an absolute path:

```
/home/lces/personal/omnigent/.venv/bin/python -c '<script>'
```

**Do not prefix `PYTHONPATH=`.** `_child_shell_env`
(`omnigent/inner/os_env.py:1559-1583`) deliberately strips omnigent's own
project root from `PYTHONPATH` for agent shell commands, because under a
tool install it points at omnigent's `site-packages` and shadows the project
venv's packages on `sys.path` (the docstring cites a 3.12 `pydantic_core`
failing to load under a 3.13 project). Setting `PYTHONPATH` by hand
re-introduces exactly the bug that function exists to fix.

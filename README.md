<div align="center">

# AI Infrastructure Security

**Vulnerability research on LLM gateways, MCP transports, and model-serving stacks**

Root-cause analysis · reproduction · detection engineering

[![Findings](https://img.shields.io/badge/findings-3-a855f7?style=for-the-badge&labelColor=030108)](#findings)
[![Focus](https://img.shields.io/badge/focus-AI%20infrastructure-22d3ee?style=for-the-badge&labelColor=030108)](#findings)
[![Companion](https://img.shields.io/badge/companion-kernel--nday--exploits-f59e0b?style=for-the-badge&labelColor=030108)](https://github.com/Aviral2642/kernel-nday-exploits)

[**Rendered index →**](https://www.aviralsrivastava.tech/research/) · [aviralsrivastava.tech](https://www.aviralsrivastava.tech)

</div>

> Linux kernel exploit work lives separately in
> [**kernel-nday-exploits**](https://github.com/Aviral2642/kernel-nday-exploits).
> Different subject, different audience.

---

## Findings

| CVE | Product | Class | Affected | Fixed |
|---|---|---|---|---|
| [CVE-2026-12940](CVE-2026-12940/) | Langflow | MCP stdio env-var injection → RCE | 1.0.0 – 1.10.1 | 1.10.2 |
| [CVE-2026-56671](CVE-2026-56671/) | ComfyUI | file-serving: traversal ×2, content-type ×2 | < 0.28.0 | 0.28.0 |
| [CVE-2026-59822](CVE-2026-59822/) | LiteLLM | MCP authentication bypass | < 1.84.0 | 1.84.0 |

A theme worth naming: all three findings are MCP or file-serving surfaces that
were mounted outside the checks their own framework already had. The transport
arrived before the review did.

---

### CVE-2026-12940 — Langflow MCP stdio environment-variable injection

N-day analysis of a defect fixed in Langflow 1.10.2. The reporter is not named
in any readable source — [GHSA-gx45-8jc3-gqqr](https://github.com/advisories/GHSA-gx45-8jc3-gqqr)
carries an empty credits array and IBM's bulletin is not publicly fetchable —
so attribution is recorded as unknown rather than guessed.

Langflow's MCP client can run a server as a local subprocess. Through 1.10.1 the
subprocess was not the configured command: it was `bash -c "exec <command> || …"`,
with the caller-supplied `env` mapping merged in last, overriding everything.

Bash reads `SHELLOPTS` from its environment at startup and enables the listed
options before running anything. With `xtrace` on, bash expands `PS4` — performing
command substitution inside it — to print each trace line. `SHELLOPTS=xtrace`
plus `PS4='$(…)'` therefore executes attacker-controlled code in Langflow's own
uid before the configured command is ever reached.

The advisory frames this as an incomplete blocklist. That holds for one of the
two paths reaching the launcher; on the other there was no blocklist at all. The
fix took both routes: [`2e46d06`](https://github.com/langflow-ai/langflow/commit/2e46d063ac9cb642503868d42c713f8f5f4d4740)
blocks the dangerous variables, [`ae7f166`](https://github.com/langflow-ai/langflow/commit/ae7f1668c608578482ebad141ecb0d3500708550)
removes the shell wrapper entirely.

One qualification is stated in the analysis rather than buried: the advisory's
unauthenticated (`PR:N`) rating could not be reproduced from source for a
default-configured 1.10.1. The routes are traced and the `AUTO_LOGIN` precondition
named. That is source reading, not a refutation of the CNA's rating.

**Contents** — [`root-cause.md`](CVE-2026-12940/root-cause.md) ·
[`reproduction.md`](CVE-2026-12940/reproduction.md) ·
[`detection.md`](CVE-2026-12940/detection.md) ·
[Nuclei template](CVE-2026-12940/langflow-cve-2026-12940.yaml)

---

### CVE-2026-56671 and siblings — ComfyUI's file-serving surface

N-day analysis of four CVEs fixed together in ComfyUI 0.28.0 by
[`96e0e35`](https://github.com/comfyanonymous/ComfyUI/commit/96e0e3585b41e1417442eaa14ec57f7b4ffcb5e0)
(PR #14734). Reporters are credited per advisory in
[`root-cause.md`](CVE-2026-56671/root-cause.md).

ComfyUI has no authentication; every route here is reachable by anyone who can
reach the port. The four are one defect class in four places — a file endpoint
takes a string from the request, picks a file on disk, and hands it to the
browser — with one of the two decisions that make that safe missing:

| CVE | Endpoint | Class |
|---|---|---|
| [CVE-2026-56671](CVE-2026-56671/) | `/experiment/models/preview/…` | path traversal |
| [CVE-2026-56673](CVE-2026-56671/) | `folder_paths.get_annotated_filepath` via `/prompt` | path traversal |
| [CVE-2026-56670](CVE-2026-56671/) | `/view` | SVG served inline |
| [CVE-2026-56672](CVE-2026-56671/) | `/userdata/{file}` | HTML/SVG served inline |

That the fix is two shared primitives — `is_within_directory()` and
`is_dangerous_content_type()` — rather than four separate patches is the
strongest evidence it is one class, not four coincidences.

Worth flagging for anyone triaging this release: the two XSS issues score
*higher* than the two traversals (8.2 vs 7.5), because scope change outweighs
the user-interaction discount. "Path traversal sounds worse than XSS" gets this
release backwards.

**Contents** — [`root-cause.md`](CVE-2026-56671/root-cause.md) ·
[`reproduction.md`](CVE-2026-56671/reproduction.md) ·
[`detection.md`](CVE-2026-56671/detection.md) ·
[Nuclei template](CVE-2026-56671/comfyui-0.28.0.yaml)

---

### CVE-2026-59822 — LiteLLM MCP authentication bypass

N-day analysis of a vulnerability reported by [**yaaras**](https://github.com/yaaras)
and fixed in LiteLLM 1.84.0.

LiteLLM decides MCP caller identity in a ladder of `if`/`elif` branches. Two of them
return an unauthenticated `UserAPIKeyAuth()` object that the rest of the stack treats
as a validated caller.

**The reported bypass**, described in [GHSA-7488-6r32-c95q](https://github.com/advisories/GHSA-7488-6r32-c95q):
when LiteLLM key validation raises 401 or 403 and an `Authorization` header is present,
the OAuth2 passthrough fallback assumes the header must be an upstream token and returns
an empty auth object. Any fabricated Bearer token reaches MCP tooling.

**A second bypass**, found and fixed by the LiteLLM maintainers in the same commit
([`73869f0`](https://github.com/BerriAI/litellm/commit/73869f0faf7d11ee21adcb5f91b8c33a340b6c2c),
"Two related issues"): a public-route check ran `".well-known" in str(request.url)`
against the full absolute URL, so the marker could be smuggled through the query string,
the hostname, or a deeper path segment. That branch sat first in the ladder and required
no header at all. It is documented in the commit message and not in the advisory.

Credit for the reported issue belongs to yaaras. Credit for finding the second branch
belongs to the LiteLLM maintainers. This repository contains the analysis of both.

**Contents** — [`root-cause.md`](CVE-2026-59822/root-cause.md) ·
[`reproduction.md`](CVE-2026-59822/reproduction.md) ·
[`detection.md`](CVE-2026-59822/detection.md) ·
[Nuclei template](CVE-2026-59822/litellm-cve-2026-59822.yaml) ·
[`lab/`](CVE-2026-59822/lab/)

---

## Method

Each finding carries the reasoning, not just a conclusion:

**`root-cause.md`** — the defect in the source, with file and line references, and the
request path from the network-facing endpoint to the flawed check.
**`reproduction.md`** — what was actually executed, against which versions, with the
observed responses on both the vulnerable and the fixed build.
**`detection.md`** — what it looks like in logs, and what artifacts it leaves behind.

Where something was not verified, the document says so rather than estimating.

## Scope and intent

Research on public, already-patched vulnerabilities, published for defensive use and
detection engineering. Reproductions run against locally-controlled instances only.

Test only systems you own or are explicitly authorised to test.

Corrections are welcome. Open an issue.

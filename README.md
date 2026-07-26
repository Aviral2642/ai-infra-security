<div align="center">

# AI Infrastructure Security

**Vulnerability research on LLM gateways, MCP transports, and model-serving stacks**

Root-cause analysis · reproduction · detection engineering

[![Findings](https://img.shields.io/badge/findings-1-a855f7?style=for-the-badge&labelColor=030108)](#findings)
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
| [CVE-2026-59822](CVE-2026-59822/) | LiteLLM | MCP authentication bypass | < 1.84.0 | 1.84.0 |

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
[`exposure.md`](CVE-2026-59822/exposure.md) ·
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
**`exposure.md`** — how to count exposed instances, and what is and is not known.

Where something was not verified, the document says so rather than estimating.

## Scope and intent

Research on public, already-patched vulnerabilities, published for defensive use and
detection engineering. Reproductions run against locally-controlled instances only.

Test only systems you own or are explicitly authorised to test.

Corrections are welcome. Open an issue.

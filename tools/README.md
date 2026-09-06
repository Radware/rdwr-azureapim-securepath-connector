# Tools

## securepath-apim-lint

Checks a SecurePath connector install on Azure API Management for the ways it can be silently
ineffective. Python 3.8 or later, no packages. Needs the Azure CLI logged in for `--live`.

    python3 tools/securepath-apim-lint.py --live -g RESOURCE_GROUP -n APIM_NAME
    python3 tools/securepath-apim-lint.py --file my-api-policy.xml --scope api

Exit code 0 means clean, 1 means findings, 2 means the instance or file could not be read.
`--json` prints the findings as a list for scripts.

| Code | What it means | What to do |
|---|---|---|
| L01 | The connector is not installed at any scope | Install the fragments (README Step 4) |
| L02 | The connector is installed at two scopes | Every request is inspected twice; keep one scope |
| L03 | An API or product policy has a section without `<base />` while the connector is at a wider scope | That API skips the connector entirely; add `<base />` first in that section |
| L04 | A policy that can reject the request (`validate-jwt`, `check-header`, `ip-filter`, `rate-limit`, `quota`, `return-response`, `validate-*`) runs before the connector | Requests it rejects are never inspected; move the include line directly after `<base />` |
| L05 | A `set-variable` has no value | Left behind by a manual merge; restore it, or use the fragments |
| L06 | Only some of the three fragments are referenced | Add the missing `include-fragment` lines |
| L07 | A required Named Value is missing | README Step 3 |
| L08 | `rdwr-app-id` contains a dot, or `rdwr-app-ep-addr` is not an `.oop.radwarecloud.net` host | README Step 3a |
| L09 | Standard v2 / Premium v2: an inspection endpoint has no matching backend entity | README Step 1, Path B; without it traffic is served uninspected |
| L10 | `rdwr-app-map` is present but not valid | Single-quoted JSON; each entry needs `app_id`, `api_key`, `endpoint`; `base_path` starts with `/` |

Run it after every install and whenever a policy on the instance changes.

The checks are text-based on purpose: API Management policy documents are not well-formed XML,
so no XML parser is involved and the tool never rewrites a document.

    python3 -m pytest tools/tests -q

### Reading a trace: `--trace`

```bash
python3 tools/securepath-apim-lint.py --trace trace.json          # readout + findings
python3 tools/securepath-apim-lint.py --trace trace.json --json   # {"summary": ..., "findings": [...]}
```

`trace.json` is the JSON returned by `gateways/managed/listTrace` (what `securepath-apim-trace.sh`
saves) or a trace downloaded from the Portal's Test tab. The readout says whether the connector ran
and in which form, what ran before it, where the inspection call went and how it ended, the verdict,
whether the response-phase log was sent, and what the origin answered. Findings:

| Code | Meaning | Where to look |
|---|---|---|
| T01 | The connector did not run on this request | Step 4 (scope), Step 2b (`<base />`), the request matched another API |
| T02 | A request-ending policy of yours ran before the connector | Step 4: move the include lines directly after `<base />` |
| T03 | The inspection call went to a host that is not `<APP_ID>.oop.radwarecloud.net` (typically the `.v1` front-end host) | Step 3a, 3c: `rdwr-app-ep-addr` or the map entry |
| T04 | The inspection call failed (`error ignored`): certificate rejected, timeout, or hostname not resolving — the message says which | Step 1 (trust for the host actually called), network path, Step 3c |
| T05 | SecurePath redirected to `wrong-api-key` | Step 3a: Application ID / API key |
| T06 | SecurePath answered 5xx; served uninspected | usually transient; contact Radware with the trace if sustained |
| T07 | Served uninspected for another reason (`X-Rdwr-Diag` value: `no_app_mapping`, `config_incomplete`, `app_map_invalid`, ...) | Step 3d, the `X-Rdwr-Diag` table in Step 5 |
| T08 | The connector ran but made no inspection call: a bypass rule matched | Step 3b (static extensions, methods not to inspect, inline trusted sources) — expected for such requests |

Exit code 0 when the trace shows a completed inspection, 1 with findings, 2 when the file is not a trace.

## securepath-apim-trace.sh

Captures one trace without the Portal and runs the readout above on it: debug token for the API →
one request through the URL your clients use, with `Apim-Debug-Authorization` → `listTrace` by the
returned `Apim-Trace-Id` → `trace.json` → readout. Bash (Cloud Shell, macOS, Linux, Git Bash);
needs `az` logged in and `curl`; `python3` optional (without it the key lines are grepped).

```bash
RG=my-rg APIM=my-apim API_ID=orders-api URL=https://api.example.com/orders/1 tools/securepath-apim-trace.sh -H "Authorization: Bearer <JWT>"
```

Everything after the script name is passed to `curl`. `METHOD` (default `GET`) and `OUT` (default
`trace.json`) are also settable. Exit 0 / 1 / 2 as for `--trace`, with 2 also covering "no debug
token" and "no `Apim-Trace-Id` in the response" (request did not reach the instance, matched a
different API than `API_ID`, or a proxy removed the header).

## securepath-apim-sync

Keeps the application map (`rdwr-app-map`) and, on Standard v2 / Premium v2, the backend
entities in step with the SecurePath applications of your Radware Cloud account. Needs a portal
API key and your Application Protection ID; the Azure CLI logged in for everything but `export`.

    python3 tools/securepath-apim-sync.py plan   -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py apply  -g RG -n APIM --cloud-api-key KEY --cloud-context CTX [--prune]
    python3 tools/securepath-apim-sync.py check  -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py export --cloud-api-key KEY --cloud-context CTX --out appmap.parameters.json
    python3 tools/securepath-apim-sync.py render -g RG -n APIM --cloud-api-key KEY --cloud-context CTX --out-dir bundle [--offline] [--prune]

| Command | Does | Exit |
|---|---|---|
| `plan` | lists each application as `add`, `update`, `unchanged` or `gone`, and the backend entities it would create; writes nothing | 0 |
| `apply` | writes only the difference; `--prune` also removes entries whose application is gone | 0 |
| `check` | for schedulers: 1 when the instance differs from the account | 0 / 1 |
| `export` | writes the map as a Bicep parameter file | 0 |
| `render` | writes what `apply` would do as a reviewable **change bundle** — commands, files and a change document — and sends nothing to Azure | 0 |

### `render`: a bundle instead of a write

For teams that do not let a tool write to Azure directly (change control, separation of duties, or
the person with the Radware Cloud key is not the person with Azure rights), `render` produces the
change as files:

| File | Content |
|---|---|
| `CHANGES.md` | the change document: target, source, mode, the `plan` table, what `apply.sh` does step by step, how to apply, how to verify, rollback, where the secrets are |
| `apply.sh` | the `az rest` commands `apply` would run, in the same order (key Named Values → fragment → backend entities on v2 tiers → removals with `--prune`). Bash; every step is a PUT, so it can be run twice |
| `securepath-app-map.fragment.xml` | the generated fragment as it will be stored; API keys appear only as `{{rdwr-app-key-…}}` references |
| `app-keys.env` | **the only file that carries API keys** (mode 600); `apply.sh` sources it. Keep it out of tickets and version control, delete it after applying |
| `backends/<name>.json` | one body per backend entity to create |
| `previous/securepath-app-map.fragment.xml` | the fragment as it is now, for rollback (difference mode only) |

Two modes. **Difference** (default): the instance is read, and the bundle contains only what
differs — exactly what `apply` would write. **`--offline`**: the instance is not read at all, so
the tool needs no Azure login; the bundle carries the whole desired state (every key, the full
fragment, every backend entity), backend entities are named after their host instead of numbered,
and the generated map is replaced as a whole (hand-written entries in `rdwr-app-map` are never
touched either way). `apply.sh` itself checks the tier before creating backend entities.

Executed on a Standard v2 instance: a difference bundle applied with `bash apply.sh`, `check`
reported `in sync`; an `--offline` bundle for the same account applied on top, `check` still
`in sync`, a second `render` then produced only a `CHANGES.md` saying so.

Applications are keyed by their domain (and the API Protection hostname when set). Entries you
wrote by hand — an API id key, `*`, a `base_path` — are never touched. Only applications in
`PROTECTING` state are included (`--include-provisioning` to add the ones still provisioning).

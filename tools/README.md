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

## securepath-apim-sync

Keeps the application map (`rdwr-app-map`) and, on Standard v2 / Premium v2, the backend
entities in step with the SecurePath applications of your Radware Cloud account. Needs a portal
API key and your Application Protection ID; the Azure CLI logged in for everything but `export`.

    python3 tools/securepath-apim-sync.py plan   -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py apply  -g RG -n APIM --cloud-api-key KEY --cloud-context CTX [--prune]
    python3 tools/securepath-apim-sync.py check  -g RG -n APIM --cloud-api-key KEY --cloud-context CTX
    python3 tools/securepath-apim-sync.py export --cloud-api-key KEY --cloud-context CTX --out appmap.parameters.json

| Command | Does | Exit |
|---|---|---|
| `plan` | lists each application as `add`, `update`, `unchanged` or `gone`, and the backend entities it would create; writes nothing | 0 |
| `apply` | writes only the difference; `--prune` also removes entries whose application is gone | 0 |
| `check` | for schedulers: 1 when the instance differs from the account | 0 / 1 |
| `export` | writes the map as a Bicep parameter file | 0 |

Applications are keyed by their domain (and the API Protection hostname when set). Entries you
wrote by hand — an API id key, `*`, a `base_path` — are never touched. Only applications in
`PROTECTING` state are included (`--include-provisioning` to add the ones still provisioning).

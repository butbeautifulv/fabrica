# DefectDojo ASPM HTML report (OSS)

Offline OSS DefectDojo does **not** support Pro Report Builder APIs (`/report_themes/`, `/report_blocks/`, `/generated_reports/`) and cannot import saved report templates. Fabrica ships a self-contained HTML generator instead.

## Generate

```bash
cd projects/fabrica

# one-time jinja2 venv
make dojo-aspm-report-venv

# offline preview (fixture)
make dojo-aspm-report-fixture

# live (secrets from cxado meta)
set -a; source ../../deploy/.secrets/cxado-k3s.env; set +a
export DEFECTDOJO_INSECURE=true   # if using self-signed TLS on :30808
make dojo-aspm-report PRODUCT=data_lake_service ENGAGEMENT='CI/CD' \
  DOJO_PUBLIC_URL=https://192.168.0.133:30808
```

Optional Make knobs (passed through to the CLI):

| Make var | CLI | Default | Purpose |
|---|---|---|---|
| `PAGE_SIZE` | `--page-size` | `25` | Findings per control-layer page |
| `MIN_SEVERITY` | `--min-severity` | `Info` | Drop findings below this severity (`Info`/`Low`/`Medium`/`High`/`Critical`) |
| `MAX_PER_LAYER` | `--max-findings-per-layer` | `0` | Hard cap per layer after severity sort (`0` = unlimited) |

Examples:

```bash
# Executive PDF: Critical+High only, smaller pages
make dojo-aspm-report PRODUCT=data_lake_service MIN_SEVERITY=High PAGE_SIZE=15

# Cap huge layers for a quick skim
make dojo-aspm-report-fixture PAGE_SIZE=5 MAX_PER_LAYER=50
```

Outputs (gitignored / CI artifacts):

| File | Purpose |
|------|---------|
| `reports/aspm-report-<product>.html` | Full engagement report (all control layers) |
| `reports/aspm-report-<product>.<layer>.html` | Partial report for one nonempty layer (`sast-semgrep`, `dast-zap`, …) — share this with an owner focused on that analysis |
| `reports/aspm-report-<product>.slices.json` | Index of slice files + finding counts |
| `reports/aspm-report-<product>.wysiwyg.md` | Paste kit for native OSS Report Builder (full only) |

CI (`aspm-html-report`) passes `--write-slices` so the job zip contains the full HTML plus one file per nonempty layer.

Local one-off (single layer only, no full sibling):

```bash
python3 scripts/dojo-render-aspm-report.py \
  --from-json tests/fixtures/aspm-slices-fixture.json \
  --only-slice dast-zap \
  --out /tmp/dast-only.html
```

Footer of the HTML lists active flags (`page-size`, `min-severity`, `redact=on`, optional `max-per-layer`, `slice=<layer>` on partials).

## Unit tests

```bash
python3 -m unittest tests.test_aspm_slice_paths tests.test_aspm_html_slices \
  tests.test_kev_catalog tests.test_kev_aspm_ssvc -v
```

Offline KEV fixture smoke:

```bash
python3 scripts/dojo-render-aspm-report.py \
  --from-json tests/fixtures/aspm-kev-fixture.json \
  --kev-catalog config/kev/cisa-kev.min.json \
  --out reports/aspm-report-fixture-kev.html
# HTML should show chip "KEV 1" and a KEV badge on the Log4Shell finding
```

## Report contents

RU cover + EN body: executive severity/SSVC/KEV chips, inline SVG severity bar, POA&M, endpoints, OWASP strip, control layers (`secrets`, `sast-semgrep`, `osa-trivy-fs`, `sca-trivy-image`, `dast-zap`, `api-fuzz-schemathesis`), coverage appendix, DefectDojo deep-links.

SSVC-lite prioritization (offline):

1. **CISA KEV** (vendored `config/kev/cisa-kev.min.json`) → SSVC **Act** — see [cisa-kev.md](cisa-kev.md)
2. **EPSS ≥ 0.5** → bump one step — Dojo `epss_score` when present, else offline [epss-offline.md](epss-offline.md) catalog fill-in
3. **Severity** → base ladder (Critical→Act, High→Attend, …)

No live HTTP to CISA/FIRST in CI; refresh catalogs with `make kev-refresh` / `make epss-refresh` on a networked host.

### UX behavior (2026-07 polish)

- **Text containment** — long JWT/base64 blobs are redacted (`[REDACTED_JWT]` / `[REDACTED_SECRET]`); descriptions wrap and scroll inside cards; long paths are middle-truncated.
- **Sort** — each control layer lists findings Critical → Info (then age, then title).
- **Collapsible layers** — `<details>` sections; start **collapsed** by default; use toolbar Expand Crit+High / Expand all. Toolbar: Collapse all / Expand Crit+High / Expand all.
- **Pagination** — every pager page shows the same full finding cards. Prev / Next / Show all. Print opens all layers but keeps page 1 only and notes `+ N more in interactive HTML`.
- **Navigation** — TOC with per-layer counts (`C# H#`), skip-to-content, back-to-top after scroll (TOC is not sticky so findings do not slide under a floating header).

## OSS Report Builder (optional)

Use the `.wysiwyg.md` kit: Cover → Executive Summary → Severities → TOC → Findings (per `test_title`) → WYSIWYG. Layouts are not persisted on OSS; rebuild each time. Prefer the HTML artifact for sharing.

## Print / PDF smoke

1. Open the HTML in Chrome/Firefox.
2. Print → Save as PDF; enable background graphics.
3. Check cover, executive chips, at least one control layer chapter.
4. Confirm collapsed layers expand for print; pager controls are hidden; page>1 content stays hidden with the “N more” note.

## Sanity vs Dojo UI

Compare severity totals in the HTML executive chips with DefectDojo Findings filtered to the same product/engagement and `active=true`. With default `--min-severity Info`, totals match the API active set. Raising `MIN_SEVERITY` shrinks executive chips and body cards on purpose.

### Evidence — `data_lake_service` / `CI/CD` (2026-07-29)

Live generate against `https://192.168.0.133:30808` (not committed; local `reports/aspm-report-data_lake_service.html`):

| Metric | API / HTML |
|---|---|
| Active findings | 2870 |
| Critical / High / Medium / Low | 254 / 2595 / 20 / 1 |
| Finding cards in HTML | 2870 |

Print-to-PDF: open HTML → Print → Save as PDF with background graphics enabled.

### UX polish regen note

Default `min-severity=Info` keeps the same finding set. With `--page-size 25`, large layers (e.g. `sast-semgrep`) paginate; JWT/`t.ipynb` cards stay inside the card box and redact secrets in the description.

**2026-07-29 UX polish:** fixture smoke + unit tests green (`page-size`, collapse, redact, min-severity). Live re-generate against `:30808` deferred — k3s/DefectDojo host temporarily unreachable (`Name or service not known`). Re-run `make dojo-aspm-report …` when the cluster is back.

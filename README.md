# STIG Dashboard

A single-file, offline dashboard for browsing and prioritizing DISA STIG checklist results — the same `.ckl` / `.cklb` output produced by **Evaluate-STIG**. Open [stig-dashboard.html](stig-dashboard.html) in a browser; everything runs client-side, nothing is uploaded anywhere.

If you've used **Nessus / ACAS**, this will feel familiar: Nessus weights raw CVSS severity by asset criticality to tell you what to fix first. This dashboard does the same for STIG findings — each finding's severity combines with an **Asset Criticality Rating (ACR)** for its host to produce a per-finding **criticality** and a per-asset **Asset Exposure Score (AES)**, so you can triage STIG results by risk instead of eyeballing raw severity counts.

## Quick start

1. Open `stig-dashboard.html` in a browser.
2. Drag and drop `.ckl` / `.cklb` files onto the page, or click **Choose file(s)**. Drop multiple files at once — a file with multiple STIGs becomes one dashboard "asset" per STIG.
3. (Optional) Upload an ACR overrides CSV via **↑ ACR Overrides (CSV)** on the Assets view.
4. Browse via the left rail: **Dashboard**, **Assets**, **STIGs**, **Findings**, **Import**.

## Sample files

[`sample checklists/`](sample%20checklists) has example `.ckl` / `.cklb` files spanning common DoD device types — switches, routers, firewalls, ESXi/vCenter, domain controllers, SQL/PostgreSQL servers, workstations, a mail server, dev-shop services, mobile devices, and more — so you can demo the dashboard without real scan data.

[`tools/generate-sample-checklists.ps1`](tools/generate-sample-checklists.ps1) generated them, from a library of reusable STIG "profiles" (title + rule topics/severities) instantiated per host with randomized-but-varied finding statuses. Run `pwsh ./tools/generate-sample-checklists.ps1` to regenerate (overwrites existing samples); add a `New-Asset` call at the bottom to add more, reusing or defining a profile — see the script header for details.

## ACR overrides (`acr override.csv`)

Overrides the dashboard's auto-calculated ACR for specific hosts. **ACAS is the source of truth** — export assets and their ACR from ACAS, reshape to this format, and import here rather than hand-assigning:

```
hostname, acr
wks-04821, 8
```

`hostname` matches a loaded asset's host name (case-insensitive); `acr` is an integer 1–10 from ACAS. Upload via **↑ ACR Overrides (CSV)** after loading the referenced checklists — unmatched/invalid rows are reported back. Hosts not in the CSV fall back to the dashboard's auto-inferred ACR (from role/hostname/STIG signals) as a stand-in until a real ACAS value is imported.

ACR combines with each finding's severity to drive the **ACR × CAT criticality matrix** (CAT I/II/III + ACR band → Low/Medium/High/Critical) and the **AES** (0–1000 per asset, ACR combined with severity-weighted exposure of Open/Not Reviewed findings — the STIG equivalent of a Nessus risk score, used to rank assets).

## Other features

- **Findings** can be filtered/sorted and exported to CSV per view (**↓ export CSV**).
- **Import** lists every loaded file/asset and lets you remove or add more.
- Reloading the page clears all loaded data — nothing is persisted.

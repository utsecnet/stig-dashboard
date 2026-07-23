# STIG Dashboard

A single-file, offline dashboard for browsing DISA STIG checklist results. Open [stig-dashboard.html](stig-dashboard.html) directly in a browser — everything runs client-side in that tab; no server, no network calls, no data upload.

## Quick start

1. Open `stig-dashboard.html` in a browser (double-click it, or drag it into a tab).
2. Drag and drop one or more checklist files onto the page, or click **Choose file(s)**.
3. (Optional) Upload the ACR overrides CSV via the **↑ ACR Overrides (CSV)** button on the Assets view.
4. Browse results using the left rail: **Dashboard**, **Assets**, **STIGs**, **Findings**, **Import**.

## The sample files in this repo

| File | Format | Purpose |
|---|---|---|
| `ubuntu.ckl` | DISA STIG Viewer CKL (XML) | Sample single-STIG checklist for a Canonical Ubuntu 20.04 host |
| `k8s-worker.ckl` | DISA STIG Viewer CKL (XML) | Sample checklist for a Kubernetes worker node |
| `IT-RJOHNSON-LAP_COMBINED_20260722-172034.cklb` | CKLB (JSON, STIG Viewer 3 / STIG Manager export) | Sample multi-STIG checklist combined for a single laptop asset (`it-rjohnson-lap`) |
| `acr override.csv` | CSV | Sample Asset Criticality Rating (ACR) overrides |

Drop any combination of `.ckl` / `.cklb` files at once — the dashboard accepts both formats interchangeably, and a single file containing multiple STIGs (multiple `iSTIG` blocks in a CKL, or multiple entries under `stigs` in a CKLB) is split into one dashboard "asset" entry per STIG.

## How the CSV ties in

`acr override.csv` overrides the dashboard's auto-calculated Asset Criticality Rating for specific hosts. Format:

```
hostname, acr
it-rjohnson-lap, 5
```

- `hostname` must match a loaded asset's host name (case-insensitive) — e.g. it matches the host name embedded in `IT-RJOHNSON-LAP_COMBINED_20260722-172034.cklb`.
- `acr` is an integer 1–10.
- Upload it via **↑ ACR Overrides (CSV)** (found in the Assets view) *after* loading the checklist files it references — unmatched hostnames and invalid values are reported back after upload.

ACR (auto-inferred from asset role/hostname/STIG signals, or overridden by the CSV) combines with each finding's severity to drive:
- The **ACR × CAT criticality matrix** (Low/Medium/High/Critical per finding)
- The **AES (Asset Exposure Score)**, 0–1000, per asset

## Other features

- **Findings** can be filtered/sorted and exported to CSV per view (**↓ export CSV**).
- **Import** view lists every loaded file/asset and lets you remove or add more.
- Reloading the page clears all loaded data — nothing is persisted or sent anywhere.

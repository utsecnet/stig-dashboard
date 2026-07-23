# STIG Dashboard

A single-file, offline dashboard for browsing and prioritizing DISA STIG checklist results — the same `.ckl` / `.cklb` output produced by **Evaluate-STIG**. Open [stig-dashboard.html](stig-dashboard.html) directly in a browser — everything runs client-side in that tab; no server, no network calls, no data upload.

If you've worked with **Nessus / ACAS**, the risk model here will feel familiar: Nessus doesn't just report a vulnerability's raw CVSS severity, it factors in the criticality of the asset it lives on (via VPR/asset criticality weighting) to tell you what to actually fix first. This dashboard applies that same idea to STIG findings — instead of leaving every CAT I/II/III finding weighted purely by its checklist severity, it combines each finding's severity with an **Asset Criticality Rating (ACR)** for the host it's on to produce a per-finding **criticality** and a per-asset **Asset Exposure Score (AES)**, so you can triage a pile of STIG results the way you'd triage a Nessus scan by risk score instead of eyeballing raw severity counts.

## Quick start

1. Open `stig-dashboard.html` in a browser (double-click it, or drag it into a tab).
2. Drag and drop one or more checklist files onto the page, or click **Choose file(s)**.
3. (Optional) Upload the ACR overrides CSV via the **↑ ACR Overrides (CSV)** button on the Assets view.
4. Browse results using the left rail: **Dashboard**, **Assets**, **STIGs**, **Findings**, **Import**.

## The sample files in this repo

[`sample checklists/`](sample%20checklists) holds a set of example `.ckl` / `.cklb` files covering common device types you'd actually see in a DoD environment — switches, an ESXi host, RHEL 9 web servers, a domain controller, a workstation, a database server, a perimeter firewall, a printer, and more — so you can load a realistic, varied mix into the dashboard without needing real scan data.

At the repo root, `IT-RJOHNSON-LAP_COMBINED_20260722-172034.cklb` is a sample multi-STIG checklist for a single laptop asset (`it-rjohnson-lap`), and `acr override.csv` is a sample ACR overrides file that matches its hostname.

Drop any combination of `.ckl` / `.cklb` files at once — the dashboard accepts both formats interchangeably, and a single file containing multiple STIGs (multiple `iSTIG` blocks in a CKL, or multiple entries under `stigs` in a CKLB) is split into one dashboard "asset" entry per STIG.

## How the CSV ties in

`acr override.csv` overrides the dashboard's auto-calculated Asset Criticality Rating for specific hosts. **ACAS is meant to be the source of truth for these values** — export your assets and their ACR ratings from ACAS, reshape that export into the two-column format below, and import it here rather than hand-assigning ACRs. Format:

```
hostname, acr
it-rjohnson-lap, 5
```

- `hostname` must match a loaded asset's host name (case-insensitive) — e.g. it matches the host name embedded in `IT-RJOHNSON-LAP_COMBINED_20260722-172034.cklb`.
- `acr` is an integer 1–10, taken directly from each asset's ACR in ACAS.
- Upload it via **↑ ACR Overrides (CSV)** (found in the Assets view) *after* loading the checklist files it references — unmatched hostnames and invalid values are reported back after upload.
- Any host not covered by the CSV falls back to the dashboard's own auto-inferred ACR (from asset role/hostname/STIG signals) — treat that as a stand-in only until the real ACAS value is imported.

ACR (auto-inferred from asset role/hostname/STIG signals, or overridden by the CSV) combines with each finding's severity — same principle as Nessus weighting a CVSS score by asset criticality — to drive:
- The **ACR × CAT criticality matrix**: CAT I/II/III severity + ACR band → Low/Medium/High/Critical per finding
- The **AES (Asset Exposure Score)**, 0–1000 per asset: ACR combined with the severity-weighted exposure of that asset's Open/Not Reviewed findings — the STIG-world equivalent of a Nessus risk score, used to rank *assets* rather than individual findings

## Other features

- **Findings** can be filtered/sorted and exported to CSV per view (**↓ export CSV**).
- **Import** view lists every loaded file/asset and lets you remove or add more.
- Reloading the page clears all loaded data — nothing is persisted or sent anywhere.

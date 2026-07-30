# STIG Dashboard

A single-file, offline dashboard for browsing and prioritizing DISA STIG checklist results — the same `.ckl` / `.cklb` output produced by **Evaluate-STIG**. Open [stig-dashboard.html](stig-dashboard.html) in a browser; everything runs client-side, nothing is uploaded anywhere.

If you've used **Nessus / ACAS**, this will feel familiar: Nessus weights raw CVSS severity by asset criticality to tell you what to fix first. This dashboard does the same for STIG findings — each finding's severity combines with an **Asset Criticality Rating (ACR)** for its host to produce a per-finding **criticality** and a per-asset **Asset Exposure Score (AES)**, so you can triage STIG results by risk instead of eyeballing raw severity counts. The Key Performance Indicator (KPI) is a single quantifiable value taken from the average of all organizational assets called the Composit Exposure Score (CES). If this value trends downward, you are doing great. If not, do better!

## Quick start

1. Open `stig-dashboard.html` in a browser.
2. Drag and drop `.ckl` / `.cklb` files onto the page, or click **Choose file(s)**. Drop multiple files at once — a file with multiple STIGs becomes one dashboard "asset" per STIG.
3. (Optional) Upload an ACR overrides CSV via **↑ ACR Overrides (CSV)** on the Assets view.
4. Browse via the left rail: **Dashboard**, **Assets**, **STIGs**, **Findings**, **Import**.

## Sample files

[`sample checklists/`](sample%20checklists) - sample checklists creating using the below tool. Usefule for generating sample data.

[`tools/generate-sample-checklists.ps1`](tools/generate-sample-checklists.ps1) - tool for creating sample checklists.

## Scoring: ACR, AES, and CES

### Asset Criticality Rating (ACR)
`ACR` is an integer 1–10 representing the assets importance to the organization. The script auto calculates each ACR based on the following STIG findings, but the values should be in sync with ACAS. See ACR Overrides below.

| ACR | Device Feature |
|---|---|
|10|Domain Controller, 
|9|DB Server, WWW Server|
|8|Hypervisor, Container Host, Perimeter Device|
|7|File, Storage Device|
|6|Server OS|
|4|Workstation OS|
|3|Mobile Device|
|2| Multifunction devices; printers|


#### ACR Overrides
Found on the Asset blade, this allows the user to override the default ACR score. **Use ACAS as the source of truth**. Requires a CSV in the following format:

```
hostname, acr
wks-04821, 8
```

### Asset Exposure Score (AES)
`AES` is an interger from 1-1000 assigned to each asset that considers the `ACR` and the weighted spread of STIG findings. Only Open and Not Reviewed findings count against it. `AES` is calculated as:

1. **Density** — a severity-weighted average across every applicable rule:

   | Status | CAT I (high) | CAT II (medium) | CAT III (low) |
   |---|---|---|---|
   | Open | 15 | 5 | 2 |
   | Not Reviewed | 5 | 1.5 | 0.5 |

   ```
   density = (sum of severity weights for Open + Not Reviewed findings) / (applicable rules)
   ```

2. **Exposure score** — density runs through a saturating curve, tapering as it approaches 1000:

   ```
   exposureScore = 1000 × (1 − e^(−density / 1.2))
   ```

3. **AES** — exposure score scaled by the asset's `ACR` (1–10), so the same finding mix scores higher on a more critical asset:

   ```
   AES = min(1000, exposureScore × (0.3 + 0.07 × ACR))
   ```

Severity threshholds: 
1. **OK** < 300
2. **Low** 300–399
3. **Medium** 400–699
4. **High** 700–899
5. **Critical** ≥ 900

![AES vs. non-compliance, by ACR](docs/aes-curve.png)

### Composite Exposure Score (CES)

`CES` is our Key Performance Indicator (KPI) — a value that can be represented over time. It is the ACR-weighted average of every asset's `AES`.
```
CES = Σ(AES × ACR) / Σ(ACR)
```

![CES: ACR-weighted vs. flat average](docs/ces-weighting.png)

In the diagram above, an average of the eight hosts' AES lands at 462, but does not consider host weight (`ACR`). Weighting by `ACR` pulls it up to 574, because the two worst-scoring hosts (DC-Primary, WebApp-Ext) also carry the highest `ACR` — closer to the actual risk picture than treating a printer's exposure the same as a domain controller's.

## Other features

- **Findings** can be filtered/sorted and exported to CSV per view (**↓ export CSV**).
- **Import** lists every loaded file/asset and lets you remove or add more.
- Nothing is written to disk. Reloading or closing the tab clears everything — this is deliberate: STIG findings are sensitive, and anything persisted to browser storage would sit there in plaintext, readable by anyone with OS-level access to the machine.

#!/usr/bin/env node
/*
 * STIG Dashboard regression test suite.
 *
 * Loads the real stig-dashboard.html from this repo, extracts the app's
 * <script> logic (stripping the outer IIFE), stitches it together with a
 * minimal fake-DOM preamble and a set of assertions into one temporary
 * script, then runs it with `node`. The assertions get direct access to
 * every top-level function/const the app defines (parseCKLB, computeAES,
 * renderFindingsList, FINDING_COLS, ...) because they're all in the same
 * scope at that point — this sidesteps the fact that top-level `let`/`const`
 * declarations don't attach to a vm sandbox's global object the way `var`
 * and function declarations do.
 *
 * Run with: node tools/regression-tests.js
 * Exits non-zero if any check fails, and prints every failure (not just
 * the first) so a bad change shows its full blast radius in one run.
 *
 * IMPORTANT: when adding a new feature or fixing a bug that a future change
 * could plausibly break again, add a check to ASSERTIONS below — that's the
 * whole point of this file. See CLAUDE.md for this project's changelog and
 * "don't lose this again" conventions.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");

const REPO_ROOT = path.join(__dirname, "..");
const HTML_PATH = path.join(REPO_ROOT, "stig-dashboard.html");
const SAMPLES_DIR = path.join(REPO_ROOT, "sample checklists");

// ---------------------------------------------------------------------
// Extract the <script> body and strip the outer `(function(){ ... })();`
// wrapper, so its contents can be dropped into a plain script instead of
// an IIFE (whose internals would otherwise be invisible to the code we
// append after it).
// ---------------------------------------------------------------------
function extractAppBody() {
  const html = fs.readFileSync(HTML_PATH, "utf8");
  const start = html.indexOf("<script>") + "<script>".length;
  const end = html.indexOf("</script>", start);
  if (start < 0 || end < 0) throw new Error("could not find <script> block in stig-dashboard.html");
  const js = html.slice(start, end);
  const lines = js.split("\n");
  const openIdx = lines.findIndex(l => l.trim() === "(function(){");
  let closeIdx = lines.length - 1;
  while (closeIdx >= 0 && lines[closeIdx].trim() === "") closeIdx--;
  if (openIdx < 0 || lines[closeIdx].trim() !== "})();") {
    throw new Error("could not find expected IIFE wrapper `(function(){ ... })();` — extraction boundaries may have shifted after a recent edit");
  }
  return lines.slice(openIdx + 1, closeIdx).join("\n");
}

// ---------------------------------------------------------------------
// Minimal fake DOM — just enough for the app's script to load without
// throwing. Nothing gets attached to a real page here; the assertions
// call the app's internal render functions directly and inspect the
// HTML strings they return.
// ---------------------------------------------------------------------
const PREAMBLE = `
function fakeEl(){
  return {
    addEventListener(){}, removeEventListener(){},
    classList:{add(){},remove(){},toggle(){},contains(){return false;}},
    style:{}, dataset:{}, children:[],
    appendChild(){}, removeChild(){}, insertBefore(){},
    querySelector(){return fakeEl();}, querySelectorAll(){return [];},
    click(){}, focus(){}, remove(){},
  };
}
global.document = {
  querySelector(){return fakeEl();},
  querySelectorAll(){return [];},
  createElement(){return fakeEl();},
  addEventListener(){},
  body: fakeEl(),
};
global.window = { addEventListener(){}, innerWidth:1024, innerHeight:768 };
global.requestAnimationFrame = ()=>{};
global.Blob = function(parts, opts){ this.parts = parts; this.type = opts && opts.type; };
global.URL = { createObjectURL(){ return "blob:fake"; }, revokeObjectURL(){} };
`;

// ---------------------------------------------------------------------
// The assertions themselves. Runs after the app body and preamble, in
// the same scope, with real sample data already loaded into \`assets\`.
// ---------------------------------------------------------------------
const ASSERTIONS = `
const fs = require("fs");
const path = require("path");

let failures = 0, passes = 0;
function check(cond, msg){
  if(cond){ passes++; return; }
  failures++;
  console.error("FAIL:", msg);
}
function section(name){ console.log("\\n--- " + name + " ---"); }

const SAMPLES_DIR = ${JSON.stringify(SAMPLES_DIR)};
const sampleFiles = fs.readdirSync(SAMPLES_DIR).filter(f => f.endsWith(".cklb") || f.endsWith(".ckl"));
if(!sampleFiles.length) throw new Error("no sample checklists found under 'sample checklists/' — cannot run regression tests");
sampleFiles.forEach(fn => {
  const p = path.join(SAMPLES_DIR, fn);
  const txt = fs.readFileSync(p, "utf8");
  const parsed = fn.endsWith(".cklb") ? parseCKLB(txt, fn) : parseCKL(txt, fn);
  parsed.forEach(a => assets.push(a));
});
console.log(\`Loaded \${assets.length} raw asset entries from \${sampleFiles.length} sample files.\`);

const hosts = groupAssetsByHost();
const allVulns = [];
latestAssets().forEach(a => a.vulns.forEach(v => allVulns.push(v)));

// ======================================================================
// Findings blade — Group/Ungroup, column filters, pagination
// (regressions caught 2026-07-25: filters and pagination were both
// silently dropped when the grouped view was added; both are checked
// here now so it can't happen unnoticed again.)
// ======================================================================
section("Findings blade — Group toggle, filters, pagination");
{
  const blade = newBlade("findings", "Findings", {});

  // Ungrouped
  let html = renderFindingsList(blade, 0);
  check(/class="group-btn[^"]*"/.test(html), "Group button present");
  check(/class="group-btn[^"]*"[^>]*>Group</.test(html), 'button reads "Group" while ungrouped');
  check(!/class="group-btn[^"]*grouped/.test(html), 'button is the blue (non-"grouped") variant while ungrouped');
  let filterCount = (html.match(/col-filter-btn/g) || []).length;
  check(filterCount >= 3, "ungrouped Findings table has column filter dropdowns (sev/status/host): found " + filterCount);
  check(html.includes('class="pagination-bar"'), "ungrouped Findings table has a pagination bar");
  check(/<span class="th-label"[^>]*data-key="source"[^>]*>Host/.test(html), 'Source column is labeled "Host" on this blade');
  // every ungrouped row must still be clickable into the finding detail pane
  check(/<tr data-blade-id="[^"]*" data-action="drill-finding" data-vuln-id="/.test(html), "ungrouped rows are clickable (drill-finding) into the finding detail pane");

  // Grouped
  blade.state.grouped = true;
  blade.state.page = 1;
  html = renderFindingsList(blade, 0);
  check(/class="group-btn[^"]*grouped[^"]*"[^>]*>Ungroup</.test(html), 'button reads "Ungroup" and uses the "grouped" (dark bg, blue text) variant while grouped');
  filterCount = (html.match(/col-filter-btn/g) || []).length;
  check(filterCount >= 2, "grouped Findings table STILL has column filter dropdowns (sev/status): found " + filterCount);
  check(html.includes('class="pagination-bar"'), "grouped Findings table STILL has a pagination bar");
  check(html.includes(">Count<"), "grouped table shows a Count column");
  check(!html.includes('data-key="source"'), "grouped table has no Host column (replaced by Count)");
  check(!html.includes('data-key="vulnId"'), "grouped table has no Vuln ID column (redundant with Rule Title, 1:1)");
  check(/<span class="th-label"[^>]*data-key="title"[^>]*>Rule Title/.test(html), "grouped table's first column is Rule Title");
  // grouped rows must ALSO still be clickable into the finding detail pane
  // (regression: this broke when grouping was first added — rows had no
  // data-action/data-vuln-id at all)
  check(/<tr data-blade-id="[^"]*" data-action="drill-finding" data-vuln-id="[^"]+"/.test(html), "grouped rows are clickable (drill-finding) into the finding detail pane");

  // Grouping correctness: counts sum to total, and match a manual tally
  const grouped = groupFindingsByTitleStatus(allVulns);
  const totalCount = grouped.reduce((s, g) => s + g.count, 0);
  check(totalCount === allVulns.length, \`grouped counts sum to total findings (\${totalCount} == \${allVulns.length})\`);
  const manualKeys = new Set(allVulns.map(v => (v.ruleTitle || "") + String.fromCharCode(1) + v.status));
  check(grouped.length === manualKeys.size, \`distinct grouped rows match manual tally (\${grouped.length} == \${manualKeys.size})\`);

  // Functional click-through: simulate what the drill-finding click handler
  // does (blade._lastVulns.find(v => v.id === repId)) and confirm it
  // resolves to a real finding whose title/status match that group's row —
  // not just that the HTML attribute is present.
  const sampleGroup = grouped.find(g => g.repId);
  check(!!sampleGroup, "found a grouped row with a repId to test click-through against");
  const resolved = allVulns.find(v => v.id === sampleGroup.repId);
  check(!!resolved, "grouped row's repId resolves to a real finding in blade._lastVulns");
  check(resolved && resolved.ruleTitle === sampleGroup.ruleTitle && resolved.status === sampleGroup.status,
    "resolved finding's rule title/status match the grouped row it came from");

  // Export must stay correct in both modes (blade._lastVulns is what "export CSV" reads)
  const b2 = newBlade("findings", "Findings", {});
  renderFindingsList(b2, 0);
  check(b2._lastVulns && b2._lastVulns.length === allVulns.length, "_lastVulns correct when ungrouped (export)");
  b2.state.grouped = true;
  renderFindingsList(b2, 0);
  check(b2._lastVulns && b2._lastVulns.length === allVulns.length, "_lastVulns still correct when grouped (export)");
}

// ======================================================================
// Findings blade — column defaults/order (Vuln ID hidden, STIG ID hidden,
// Rule Title first)
// ======================================================================
section("Findings blade — column config");
{
  const vulnIdCol = FINDING_COLS.find(c => c.key === "vulnId");
  const idCol = FINDING_COLS.find(c => c.key === "id");
  check(vulnIdCol.default === false, "Vuln ID column hidden by default");
  check(idCol.default === false && !idCol.locked, "STIG ID column hidden by default and togglable");
  check(FINDING_COLS[0].key === "vulnId", "Vuln ID is still the first column definition (reappears first if re-enabled)");
  check(FINDING_COLS[1].key === "title", "Rule Title is the first visible column by default");

  // Vuln ID must remain searchable even while its column is hidden
  const target = allVulns.find(v => v.vulnNum);
  check(!!target, "found a sample finding with a Vuln ID to test search against");
  const blade = newBlade("findings", "Findings", {});
  blade.state.search = target.vulnNum;
  const filtered = filterVulns(allVulns, blade.state);
  check(filtered.some(v => v.vulnNum === target.vulnNum), "searching by Vuln ID still matches, even though the column is hidden");
}

// ======================================================================
// Finding detail — "Affected Assets" sub-table (only when opened from a
// grouped Findings row): sortable/filterable/exportable, correct row
// count, drill-through to Asset Detail, and correctly absent everywhere
// else (ungrouped Findings row, Asset Detail's own findings table).
// ======================================================================
section("Finding detail — Affected Assets (grouped context only)");
{
  const findingsBlade = newBlade("findings", "Findings", {});
  findingsBlade.state.grouped = true;
  renderFindingsList(findingsBlade, 0);
  bladeStack = [findingsBlade];

  const filtered2 = filterVulns(findingsBlade._lastVulns, findingsBlade.state);
  const grouped = sortGroupedRows(groupFindingsByTitleStatus(filtered2), findingsBlade.state);
  const targetGroup = grouped.find(g => g.count > 1);
  check(!!targetGroup, "found a grouped row with count > 1 to test against");

  if (targetGroup) {
    const repVuln = findingsBlade._lastVulns.find(v => v.id === targetGroup.repId);
    check(!!repVuln, "representative vuln resolves from the group's repId");

    const fdBlade = newBlade("findingDetail", repVuln.ruleVer || repVuln.ruleTitle, { vuln: repVuln, parentBladeId: findingsBlade.id });
    bladeStack.push(fdBlade);
    const html = renderFindingDetail(fdBlade, 1);

    check(html.includes('class="fd-affected"'), "Affected Assets section renders when opened from a grouped row");
    check(/data-key="hostName"[^>]*>Host Name/.test(html), "Host Name column present");
    check(/data-key="hostIp"[^>]*>IP Address/.test(html), "IP Address column present");
    check(/data-key="acr"[^>]*>ACR/.test(html), "ACR column present");
    check(/data-key="aes"[^>]*>AES/.test(html), "AES column present");
    check(/data-filter-key="acr"/.test(html), "ACR column is filterable");
    check(/data-filter-key="aes"/.test(html), "AES column is filterable");
    check(html.includes('data-action="export-affected-assets"'), "export button present");

    const rowCount = (html.match(/<tr data-action="drill" data-blade-index="1" data-type="assetDetail"/g) || []).length;
    check(rowCount === targetGroup.count, \`affected-assets row count (\${rowCount}) matches group count (\${targetGroup.count})\`);
    check(fdBlade._lastAffectedAssets && fdBlade._lastAffectedAssets.length === targetGroup.count, "_lastAffectedAssets set for export, matches row count");

    // Default sort: Host Name ascending
    const names = fdBlade._lastAffectedAssets.map(r => r.hostName);
    const sortedNames = names.slice().sort((a, b) => a.localeCompare(b));
    check(JSON.stringify(names) === JSON.stringify(sortedNames), "default sort is by Host Name ascending");

    // Sort by AES descending
    fdBlade.state.sortKey = "aes";
    fdBlade.state.sortDir = -1;
    renderFindingDetail(fdBlade, 1);
    const aesVals = fdBlade._lastAffectedAssets.map(r => r.aes);
    let aesDesc = true;
    for (let i = 1; i < aesVals.length; i++) { if (aesVals[i] > aesVals[i - 1]) aesDesc = false; }
    check(aesDesc, "sorting by AES descending works");

    // ACR band filter narrows rows correctly
    fdBlade.state.sortKey = "hostName"; fdBlade.state.sortDir = 1;
    const anyBand = acrBand(fdBlade._lastAffectedAssets[0].acrInfo.value);
    fdBlade.state.colFilters.acr = new Set([anyBand]);
    renderFindingDetail(fdBlade, 1);
    check(fdBlade._lastAffectedAssets.every(r => acrBand(r.acrInfo.value) === anyBand), "ACR band filter narrows rows correctly");
    fdBlade.state.colFilters.acr = new Set();

    // Export doesn't throw, and names the file "<v-id> - affected assets.csv"
    let exportOk = true;
    let capturedDownloadName = null;
    const realCreateElement = document.createElement;
    document.createElement = function(tag){
      const el = realCreateElement.call(document, tag);
      if(tag === "a"){
        Object.defineProperty(el, "download", {
          set(v){ capturedDownloadName = v; },
          get(){ return capturedDownloadName; },
        });
      }
      return el;
    };
    try { exportAffectedAssetsCSV(fdBlade._lastAffectedAssets, repVuln.vulnNum); } catch (e) { exportOk = false; console.error(e); }
    document.createElement = realCreateElement;
    check(exportOk, "exportAffectedAssetsCSV runs without throwing");
    check(capturedDownloadName === repVuln.vulnNum + " - affected assets.csv",
      \`export filename is "<v-id> - affected assets.csv" (got "\${capturedDownloadName}")\`);
  }

  // NEGATIVE: ungrouped Findings row must not show the section
  const findingsBlade2 = newBlade("findings", "Findings", {});
  findingsBlade2.state.grouped = false;
  renderFindingsList(findingsBlade2, 0);
  bladeStack = [findingsBlade2];
  const someVuln = findingsBlade2._lastVulns[0];
  const fdBlade2 = newBlade("findingDetail", someVuln.ruleVer, { vuln: someVuln, parentBladeId: findingsBlade2.id });
  bladeStack.push(fdBlade2);
  const html2 = renderFindingDetail(fdBlade2, 1);
  check(!html2.includes("fd-affected"), "no Affected Assets section when opened from an UNGROUPED findings row");

  // NEGATIVE: Asset Detail's own findings table has no grouping concept at all
  const assetBlade = newBlade("asset-detail", "Asset", { hostKey: hosts[0].hostKey });
  renderAssetDetail(assetBlade, 0);
  bladeStack = [assetBlade];
  const assetVuln = (assetBlade._lastVulns || [])[0];
  if (assetVuln) {
    const fdBlade3 = newBlade("findingDetail", assetVuln.ruleVer, { vuln: assetVuln, parentBladeId: assetBlade.id });
    bladeStack.push(fdBlade3);
    const html3 = renderFindingDetail(fdBlade3, 1);
    check(!html3.includes("fd-affected"), "no Affected Assets section when opened from Asset Detail");
  }
}

// ======================================================================
// Asset Detail — combined ACR row, AES badge on chart, compliance split row
// ======================================================================
section("Asset Detail — layout");
{
  const host = hosts[0];
  const blade = newBlade("asset-detail", "Asset", { hostKey: host.hostKey });
  const html = renderAssetDetail(blade, 0);
  check(html.includes('class="acr-row"'), "ACR badge + override dropdown share one row");
  check(html.includes('class="aes-trend-badge-center"'), "AES badge sits centered in the AES-over-time chart header");
  check(html.includes('class="compliance-split-row"') && html.includes('class="tiles-stack"'), "compliance bars + status tiles combined into one row");
  check(html.includes('<div class="lbl">N/A</div>'), "Not Applicable tile shortened to N/A");
}

// ======================================================================
// Dashboard — CES trend on Assets tab only, combined row on Findings tab
// ======================================================================
section("Dashboard");
{
  const bladeAssets = newBlade("dashboard", "Dashboard", {});
  const htmlAssets = renderDashboard(bladeAssets, 0);
  check(htmlAssets.includes("CES Over Time"), "CES Over Time chart present on Assets tab");

  const bladeFindings = newBlade("dashboard", "Dashboard", {});
  bladeFindings.state.dashboardTab = "findings";
  const htmlFindings = renderDashboard(bladeFindings, 0);
  check(!htmlFindings.includes("CES Over Time"), "CES Over Time chart does NOT appear on Findings tab");
  check(htmlFindings.includes('class="compliance-split-row"') && htmlFindings.includes('class="tiles-stack"'), "Findings tab combines compliance bars + tiles into one row");
}

// ======================================================================
// AES / CES core math sanity checks
// ======================================================================
section("AES / CES math");
{
  const host = hosts.find(h => h.hostKey && h.stigs && h.stigs.length);
  const acrInfo = getACR(host.hostKey, host);
  const aesInfo = computeAES(host, acrInfo.value);
  check(aesInfo.aes >= 0 && aesInfo.aes <= 1000, "AES stays within 0-1000 bounds");
  const rows = buildAssetRows(hosts);
  const ces = computeCES(rows);
  check(ces >= 0 && ces <= 1000, "CES stays within 0-1000 bounds");
  const points = cesHistory();
  if(points.length){
    const last = points[points.length-1];
    check(Math.abs(last.aes - ces) <= 1, "latest CES-over-time point matches current dashboard CES (within rounding)");
  }
}

// ======================================================================
// Trend chart x-axis labels — dates must never collide. Short histories
// stay horizontal; longer ones angle diagonally (-45°) and, past a point,
// thin out. Every point keeps its hover tooltip either way.
// ======================================================================
section("Trend chart — date label collision");
{
  const mk = n => Array.from({length:n}, (_,i)=>({date:new Date(2026,6,1+i), aes:400-i}));
  const gap = svg => {
    const xs = [...svg.matchAll(/<text x="([\\d.]+)"[^>]*>2026-/g)].map(m=>parseFloat(m[1])).sort((a,b)=>a-b);
    let g = Infinity;
    for(let i=1;i<xs.length;i++) g = Math.min(g, xs[i]-xs[i-1]);
    return {gap:g, count:xs.length};
  };

  // At a 45° angle, a ~54px-wide/11px-tall label's horizontal footprint is
  // (54*cos45 + 11*sin45) ~= 46px, plus the same +2px pad aesTimelineSvg uses.
  [1,2,5,10,13,14,15,20,25,30,40,60,90,120,200,365].forEach(n=>{
    const svg = aesTimelineSvg(mk(n), "AES");
    const rotated = svg.includes("rotate(-45");
    const {gap:g, count} = gap(svg);
    const need = rotated ? 48 : 54;   // angled labels need their diagonal footprint, not their full width
    check(count < 2 || g >= need,
      \`\${n}-point series: labels do not overlap (\${rotated?"angled":"horizontal"}, min gap \${g===Infinity?"n/a":g.toFixed(1)}px)\`);
    // No matter how labels are thinned, every data point keeps its dot+tooltip.
    check((svg.match(/<circle/g)||[]).length === n, \`\${n}-point series: every point still plotted\`);
    check((svg.match(/<title>/g)||[]).length === n, \`\${n}-point series: every point keeps its hover tooltip\`);
  });

  // Short histories must NOT angle — angling is the fallback, not the default.
  check(!aesTimelineSvg(mk(5), "AES").includes("rotate(-45"), "a 5-point history keeps horizontal date labels");
  check(aesTimelineSvg(mk(25), "AES").includes("rotate(-45"), "a 25-point history angles its date labels");
  // And it must not be a full vertical flip anymore.
  check(!aesTimelineSvg(mk(25), "AES").includes("rotate(-90"), "a 25-point history is angled, not fully vertical");

  // Angling grows the SVG downward rather than squashing the plot area.
  const short = aesTimelineSvg(mk(5), "AES").match(/viewBox="0 0 (\\d+) (\\d+)"/);
  const tall  = aesTimelineSvg(mk(25), "AES").match(/viewBox="0 0 (\\d+) (\\d+)"/);
  check(short[2] === "220", "unrotated chart keeps its original 220px viewBox height");
  check(+tall[2] > +short[2], "angled chart grows taller to make room for diagonal labels");

  // First and last dates are always labeled so the range stays readable.
  const big = aesTimelineSvg(mk(200), "AES");
  check(big.includes(">2026-07-01<"), "first date is always labeled, even on a long series");
  const lastDate = formatDateISO(mk(200)[199].date);
  check(big.includes(">"+lastDate+"<"), "last date is always labeled, even on a long series");
}

// ======================================================================
// CCI -> RMF control number mapping (Control Number column: top-level
// Findings blade + the per-asset findings table inside Asset Detail — both
// share FINDING_COLS/the "findings" col-prefs key, so one toggle covers
// both. Deliberately NOT on the Assets list table, which lists one row per
// host, not per finding.) Source-data quirks this must handle: a CCI id can
// carry a trailing " deprecated" suffix in the DISA export it's built from,
// and a finding's raw cci field can mix legacy SV-/V- ids in with the real
// CCI-###### ids (this is exactly what a user spotted in the CCI column of
// sw-core03.cklb — "SV-110523, V-101419, CCI-000382" — which is why this
// feature exists).
// ======================================================================
section("CCI -> RMF control number mapping");
{
  check(CCI_CONTROL_MAP["CCI-000382"] === "CM-7", "known CCI resolves to its control number");
  check(CCI_CONTROL_MAP["CCI-000191"] === "IA-5(1)", "a CCI whose source row carries a trailing \\" deprecated\\" marker still resolves under its bare id");
  check(!("CCI-000191 deprecated" in CCI_CONTROL_MAP), "the \\" deprecated\\" marker itself is not a map key");

  // sw-core03.cklb's raw ccis array mixes legacy SV-/V- ids in with the real
  // CCI id — controlNumbersForCciField must pull out just the CCI token.
  check(controlNumbersForCciField("SV-110523, V-101419, CCI-000382") === "CM-7",
    "legacy SV-/V- ids mixed into a cci field are ignored; only the CCI token resolves");

  // A CCI that legitimately maps to more than one control stays a
  // comma-separated, de-duplicated, sorted list.
  check(controlNumbersForCciField("CCI-000296, CCI-000305") === "CM-2, CM-2(1), CM-2(4), CM-7(2)",
    "multiple CCIs resolve to their combined, de-duplicated, sorted control list");

  check(controlNumbersForCciField("CCI-999999") === "", "an unmapped/unknown CCI resolves to nothing, not a crash");
  check(controlNumbersForCciField("") === "" && controlNumbersForCciField(undefined) === "", "empty/missing cci field resolves to an empty string");

  // Column config: on the Findings columns (shared by the top-level Findings
  // blade and the Asset Detail findings table), hidden by default like CCI
  // itself — and deliberately absent from ASSET_COLS (the host-list table).
  const findingCtrlCol = FINDING_COLS.find(c => c.key === "control");
  check(!!findingCtrlCol && findingCtrlCol.label === "Control Number" && findingCtrlCol.default === false,
    'Findings columns have a hidden-by-default "Control Number" column');
  check(!ASSET_COLS.some(c => c.key === "control"),
    "Assets (host-list) table does NOT get a Control Number column — that table is one row per host, not per finding");

  const knownFinding = allVulns.find(v => (v.cci||"").includes("CCI-000382"));
  check(!!knownFinding, "found the sample finding with CCI-000382 to check the rendered cell against");

  // Top-level Findings blade: the real sample finding with CCI-000382
  // renders its mapped control number once the column is switched on.
  getVisibleCols("findings", FINDING_COLS).add("control");
  const findingsHtml = renderFindingsList(newBlade("findings", "Findings", {}), 0);
  check(findingsHtml.includes(">Control Number<"), "Control Number header renders on the top-level Findings blade once enabled");
  check(findingsHtml.includes(">CM-7<"), "the CCI-000382 finding's row shows its mapped control number (CM-7) on the Findings blade");

  // Asset Detail's own per-host findings table — the pane you land on after
  // clicking into an asset from the Assets list — must show the same column
  // and value, since it renders through the same findingsTableHtml/FINDING_COLS.
  const hostWithFinding = hosts.find(h => (h.stigs||[]).some(a => a.vulns.some(v => (v.cci||"").includes("CCI-000382"))));
  check(!!hostWithFinding, "found the host that owns the CCI-000382 finding, to test its Asset Detail pane");
  const assetDetailHtml = renderAssetDetail(newBlade("asset-detail", "Asset", { hostKey: hostWithFinding.hostKey }), 0);
  check(assetDetailHtml.includes(">Control Number<"), "Control Number header renders inside Asset Detail's findings table once enabled");
  check(assetDetailHtml.includes(">CM-7<"), "Asset Detail's findings table shows the mapped control number (CM-7) for the matching row");
  getVisibleCols("findings", FINDING_COLS).delete("control");

  // CSV export includes the new column, correctly mapped.
  let capturedBlob = null;
  const realCreateObjectURL = URL.createObjectURL;
  URL.createObjectURL = function(b){ capturedBlob = b; return realCreateObjectURL(b); };
  exportCSV([knownFinding], "test");
  URL.createObjectURL = realCreateObjectURL;
  const csvText = capturedBlob ? capturedBlob.parts[0] : "";
  check(csvText.includes("Control Number"), "CSV export header row includes \\"Control Number\\"");
  check(csvText.includes("CM-7"), "CSV export row includes the mapped control number");

  // Control Number must be searchable even while its column is hidden by
  // default — same convention as Vuln ID (tested above).
  const searchBlade = newBlade("findings", "Findings", {});
  searchBlade.state.search = "CM-7";
  const bySearch = filterVulns(allVulns, searchBlade.state);
  check(bySearch.some(v => v.id === knownFinding.id), "searching by Control Number (\\"CM-7\\") matches the CCI-000382 finding, even with the column hidden");
  searchBlade.state.search = "cm-7";
  check(filterVulns(allVulns, searchBlade.state).some(v => v.id === knownFinding.id), "Control Number search is case-insensitive");

  // The search box placeholder should be a plain, unconfusing "Search..."
  // rather than naming internal fields the user won't recognize (a prior
  // version said "Search rule title, STIG ID, group..." — "group" in
  // particular confused users, since it doesn't correspond to anything
  // visible in the UI).
  const controlsBarHtml = controlsHtml(searchBlade.id, searchBlade.state, FINDING_COLS, "findings", true);
  check(controlsBarHtml.includes('placeholder="Search..."'), 'Findings search box placeholder is a plain "Search..."');
  check(!controlsBarHtml.includes("STIG ID, group"), "Findings search box no longer names internal fields like \\"group\\" in its placeholder");
}

// ======================================================================
// Security — output encoding and CSV formula injection.
// Checklist content (filenames, hostnames, rule text, comments) is
// untrusted input: it comes from whatever scanner/operator produced the
// file. These guard the escaping boundaries.
// ======================================================================
section("Security — escaping and CSV injection");
{
  // --- HTML attribute escaping for a hostile filename -----------------
  // v.id is derived from the filename, and is emitted into the
  // data-vuln-id attribute. An unescaped quote there breaks out of the
  // attribute and injects arbitrary handlers.
  const hostileName = 'evil" onmouseover="alert(1)" x=".cklb';
  const donor = assets[0];
  const craft = {
    id: hostileName + "_0-0",
    ruleTitle: 'title with "quotes" & <b>markup</b>',
    ruleVer: "RV-1", vulnNum: "V-1", severity: "high", status: "Open",
    groupTitle: "", discussion: "", checkContent: "", fixText: "",
    comments: "", cci: "", _sourceLabel: '<img src=x onerror=alert(1)>',
  };
  const blade = newBlade("findings", "Findings", {});
  const html = findingsTableHtml(blade, [craft], true, [], "Host", true, []);
  check(!html.includes('onmouseover="alert(1)"'),
    "hostile filename in data-vuln-id cannot break out of the attribute");
  check(html.includes("&quot;") || html.includes("&#39;"),
    "hostile filename is entity-escaped in the row attribute");
  check(!/<img src=x onerror/.test(html),
    "hostile source label is escaped, not injected as a live <img> tag");
  check(!html.includes("<b>markup</b>"),
    "hostile rule title is escaped, not injected as live markup");

  // --- CSV formula injection ------------------------------------------
  // Excel/Sheets execute a cell beginning with = + - @ as a formula.
  check(csvCell("=cmd|'/c calc'!A1").startsWith("\\"'="),
    "CSV cell starting with = is neutralized with a leading apostrophe");
  ["+1+1", "-1+1", "@SUM(A1)"].forEach(danger=>{
    check(csvCell(danger).startsWith("\\"'"), \`CSV cell starting with \${danger[0]} is neutralized\`);
  });
  check(csvCell("normal text") === '"normal text"', "ordinary CSV cells are untouched apart from quoting");
  check(csvCell('has "quotes"') === '"has ""quotes"""', "embedded quotes are still doubled correctly");
  // 0 must survive as "0" — the old String(c||"") idiom turned it into ""
  check(csvCell(0) === '"0"', "numeric zero exports as 0, not an empty cell");
  check(csvCell(null) === '""' && csvCell(undefined) === '""', "null/undefined export as empty cells");
}

// ======================================================================
// Robustness / performance invariants
// ======================================================================
section("Robustness and performance invariants");
{
  // buildAssetRow must tolerate being used as a .map() callback, where the
  // second argument is an array index rather than the history Map.
  let mapCallbackOk = true;
  try { hosts.slice(0, 3).map(buildAssetRow); } catch (e) { mapCallbackOk = false; }
  check(mapCallbackOk, "buildAssetRow survives being passed straight to .map() (index as 2nd arg)");

  // The shared-map path and the standalone path must agree exactly.
  const counts = historyCountsByHost();
  const viaShared = hosts.map(h => buildAssetRow(h, counts).history);
  const viaSolo = hosts.map(h => buildAssetRow(h).history);
  check(JSON.stringify(viaShared) === JSON.stringify(viaSolo),
    "history counts identical whether computed per-row or from the shared map");
  check(viaShared.every(n => n >= 1), "every host reports at least one imported checklist");

  // groupAssetsByHost must ignore a non-array argument rather than crash.
  let groupOk = true;
  try { groupAssetsByHost(0); groupAssetsByHost(undefined); } catch (e) { groupOk = false; }
  check(groupOk, "groupAssetsByHost tolerates a non-array argument");
  check(groupAssetsByHost(latestAssets()).length === groupAssetsByHost().length,
    "passing a precomputed latestAssets() yields the same host grouping");

  // parseScanDate memoization must not leak mutable state between callers.
  const sample = assets.find(a => a.scanDate && parseScanDate(a.scanDate));
  if(sample){
    const d1 = parseScanDate(sample.scanDate);
    const d2 = parseScanDate(sample.scanDate);
    check(d1.getTime() === d2.getTime(), "parseScanDate returns a consistent value when memoized");
    check(parseScanDate("") === null && parseScanDate(null) === null, "parseScanDate still rejects empty input");
    check(parseScanDate("not a date") === null, "parseScanDate still rejects unparseable input");
  }
}

// ======================================================================
// AES/CES history — one checkpoint per calendar day, not per exact scan
// timestamp. Regression: Evaluate-STIG stamps each STIG in a multi-STIG
// CKLB with its own evaluate-stig.time, typically a few seconds or minutes
// apart — a single one-host, one-day import was fracturing into as many
// "history" points as it had STIGs, all rendering the same date on the
// x-axis (reported by a user: uploading one CKLB for one host showed ~11
// same-day points on the AES Over Time chart).
//
// This section mutates the shared \`assets\` array, so it must run LAST —
// every earlier section already ran against the pristine sample-data state.
// ======================================================================
section("AES/CES history — day-granularity checkpoints");
{
  const mkVuln = status => ({id:"v", vulnNum:"V-1", ruleVer:"SV-1", ruleTitle:"t", severity:"medium", status, groupTitle:"", discussion:"", checkContent:"", fixText:"", cci:"", comments:""});
  const HOST = "REGRESSION-MULTI-STIG-HOST";

  // Day 1: three STIGs for the same host, same calendar day, each stamped a
  // few minutes apart — exactly the real-world shape that triggered the bug.
  assets.push({id:"r1", fileName:"r1.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG A", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-22T09:00:00Z", vulns:[mkVuln("Open"), mkVuln("NotAFinding")]});
  assets.push({id:"r2", fileName:"r2.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG B", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-22T09:03:12Z", vulns:[mkVuln("Open"), mkVuln("NotAFinding")]});
  assets.push({id:"r3", fileName:"r3.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG C", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-22T09:07:45Z", vulns:[mkVuln("Open"), mkVuln("NotAFinding")]});

  const day1Points = aesHistory(HOST);
  check(day1Points.length === 1, \`a single-day, multi-STIG import produces exactly one history point (got \${day1Points.length})\`);
  check(day1Points.length && formatDateISO(day1Points[0].date) === "2026-07-22", "that one point is dated the calendar day of the scans, not fractured across their exact timestamps");

  // Day 2: two of those STIGs re-scanned the next day, again a few minutes
  // apart — must add exactly one MORE point (real day-over-day history must
  // still work), not merge into day 1 and not add two more.
  assets.push({id:"r4", fileName:"r4.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG A", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-23T09:00:00Z", vulns:[mkVuln("NotAFinding"), mkVuln("NotAFinding")]});
  assets.push({id:"r5", fileName:"r5.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG B", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-23T09:05:30Z", vulns:[mkVuln("NotAFinding"), mkVuln("NotAFinding")]});

  const day2Points = aesHistory(HOST);
  check(day2Points.length === 2, \`a genuine second scan day adds exactly one more point (got \${day2Points.length})\`);
  check(day2Points.length === 2 && formatDateISO(day2Points[1].date) === "2026-07-23", "the second point is dated the second calendar day");
  check(day2Points.length === 2 && day2Points[1].aes < day2Points[0].aes, "compliance improving on day 2 (more NotAFinding) is reflected as a lower AES");

  // Fleet-wide cesHistory() must show the same day-granularity behavior —
  // no more history points than there are distinct calendar days across
  // every asset now loaded (real sample data + the synthetic host above).
  const distinctDays = new Set(assets.map(a => a.scanDate && parseScanDate(a.scanDate)).filter(Boolean).map(d => formatDateISO(d)));
  const cesPoints = cesHistory();
  check(cesPoints.length === distinctDays.size,
    \`cesHistory() has exactly one point per distinct calendar day across all assets (\${cesPoints.length} points, \${distinctDays.size} distinct days)\`);
}

console.log(\`\\n\${passes} passed, \${failures} failed.\`);
if(failures > 0) process.exit(1);
`;

// ---------------------------------------------------------------------
// Assemble and run
// ---------------------------------------------------------------------
const appBody = extractAppBody();
const combined = [PREAMBLE, appBody, ASSERTIONS].join("\n\n");

const tmpFile = path.join(os.tmpdir(), `stig-dashboard-regression-${Date.now()}.js`);
fs.writeFileSync(tmpFile, combined);
let exitCode = 0;
try {
  execFileSync(process.execPath, [tmpFile], { stdio: "inherit" });
} catch (err) {
  // The child already printed its own FAIL lines and summary; just propagate
  // its exit code without an extra Node stack trace on top.
  exitCode = (err && typeof err.status === "number") ? err.status : 1;
} finally {
  fs.unlinkSync(tmpFile);
}
process.exit(exitCode);

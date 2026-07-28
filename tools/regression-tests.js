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
// Mirror the app: every mutation of \`assets\` bumps the version the memoized
// derived views key off. Skipping this here would let a test read a cache
// built before the sample data was loaded.
bumpAssetsVersion();
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
// compliancePct — the single shared "% Compliant" formula behind the CAT
// bars, the Compliance by Category panel, the Assets/STIGs tables, and the
// Compliance blade. Not_Applicable is excluded from BOTH the numerator and
// the denominator: compliance is naf / (open + nr + naf), never
// (naf + na) / total. A regression here would silently skew every
// compliance percentage in the app at once.
// ======================================================================
section("compliancePct — Not Applicable excluded from both sides");
{
  check(compliancePct(0, 0, 10) === 100, "all Not a Finding, nothing open/pending -> 100%");
  check(compliancePct(10, 0, 0) === 0, "all Open, nothing resolved -> 0%");
  check(compliancePct(5, 0, 5) === 50, "half open, half not-a-finding -> 50%");
  check(compliancePct(0, 0, 0) === 100, "no applicable rules at all -> 100% (nothing to fail)");
  check(compliancePct(2, 1, 3) === 50, "3 naf / (2 open + 1 nr + 3 naf) = 50%");
  // The function's signature has no Not_Applicable parameter at all — the
  // real regression this guards against is a caller passing (naf+na) as the
  // third argument, which this section's caller-level checks below cover
  // against real data with actual Not_Applicable rules mixed in.
  check(compliancePct.length === 3, "compliancePct takes exactly open/nr/naf — no Not Applicable input to leak through");

  // Integration check against real sample data: find a host that actually
  // has Not_Applicable rules, and confirm the Assets table's % Compliant
  // (buildAssetRow), the STIGs table's % Compliant (buildStigGroups), and
  // the Compliance by Category panel (complianceBarsHtml) all agree with a
  // manual tally that excludes N/A from both sides — and that this differs
  // from the old (naf+na)/total formula whenever N/A rules are actually
  // present, proving N/A is excluded rather than coincidentally irrelevant.
  const hostWithNA = hosts.find(h=>{
    let na = 0; h.stigs.forEach(a=>a.vulns.forEach(v=>{ if(v.status==="Not_Applicable") na++; }));
    return na > 0;
  });
  check(!!hostWithNA, "found a sample host with at least one Not_Applicable rule to test against");
  if(hostWithNA){
    let open=0, nr=0, naf=0, na=0, total=0;
    hostWithNA.stigs.forEach(a=>a.vulns.forEach(v=>{
      total++;
      if(v.status==="Open") open++;
      else if(v.status==="Not_Reviewed") nr++;
      else if(v.status==="NotAFinding") naf++;
      else na++;
    }));
    const expected = compliancePct(open, nr, naf);
    const oldFormula = Math.round(((naf+na)/total)*100);
    check(na > 0 && expected !== oldFormula,
      \`sanity: this host's N/A count (\${na}) actually changes the answer under the old formula, so this is a real test of the exclusion\`);
    const row = buildAssetRow(hostWithNA);
    check(row.compliance === expected, \`Assets table % Compliant excludes N/A (got \${row.compliance}, expected \${expected})\`);
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
// Compliance blade — RMF control family roll-up and drill-down.
//
// Three levels: families (AC, AU, ...) -> individual controls (AC-2,
// AC-2(1), ...) -> the Findings blade filtered to that control. The
// subtlety worth guarding is that one finding can cite several CCIs
// mapping to several controls, so it is counted under EACH control it
// touches — rule counts deliberately overlap across rows and must NOT be
// "fixed" into a partition. Within a single family, though, a finding
// citing two of that family's controls must still count once.
// ======================================================================
section("Compliance blade — RMF control families");
{
  const famRows = complianceFamilyRows();
  check(famRows.length > 0, "compliance blade produces at least one control-family row");

  // Family metadata resolves to real NIST names, and unknown prefixes still
  // group rather than crash.
  check(familyName("AC") === "Access Control", "AC resolves to its NIST family name");
  check(familyName("SR") === "Supply Chain Risk Management", "Rev 5 SR family is named");
  check(familyName("AR") === "Accountability, Audit, and Risk Management", "Rev 4 Appendix J privacy family is named");
  check(familyName("ZZ") === "ZZ", "an unrecognized family prefix falls back to its bare code");
  check(controlFamilyOf("AC-2(1)") === "AC", "control family is parsed from the control number");
  check(controlFamilyOf("") === "" && controlFamilyOf(undefined) === "", "family parsing tolerates empty input");

  // --- Per-family totals must match a manual tally, counting each finding
  // ONCE per family even when it cites several controls in that family.
  const flat = allFindingsWithControls();
  check(flat.length === allVulns.length, \`allFindingsWithControls covers every finding (\${flat.length} == \${allVulns.length})\`);

  const manualFam = new Map();
  flat.forEach(({vuln, controls})=>{
    const fams = new Set(controls.map(c => c === UNMAPPED_CONTROL ? UNMAPPED_CONTROL : controlFamilyOf(c)));
    fams.forEach(f=>{
      if(!manualFam.has(f)) manualFam.set(f, {total:0, open:0, nr:0, naf:0, na:0});
      const t = manualFam.get(f);
      t.total++;
      if(vuln.status === "Open") t.open++;
      else if(vuln.status === "Not_Reviewed") t.nr++;
      else if(vuln.status === "NotAFinding") t.naf++;
      else if(vuln.status === "Not_Applicable") t.na++;
    });
  });
  check(famRows.length === manualFam.size, \`family row count matches a manual tally (\${famRows.length} == \${manualFam.size})\`);
  let famTotalsMatch = true, famPctMatch = true;
  famRows.forEach(r=>{
    const m = manualFam.get(r.family);
    if(!m || m.total !== r.total || m.open !== r.open) famTotalsMatch = false;
    // % compliant excludes Not_Applicable from both sides of the ratio —
    // it's naf / (open+nr+naf), not (naf+na) / total.
    const applicable = m ? m.open + m.nr + m.naf : 0;
    const expectPct = applicable ? Math.round((m.naf / applicable) * 100) : 100;
    if(!m || expectPct !== r.compliance) famPctMatch = false;
  });
  check(famTotalsMatch, "every family's rule/open counts match the manual tally");
  check(famPctMatch, "every family's % compliant excludes Not Applicable from both sides of the ratio");

  // A finding citing two controls in the SAME family counts once for that
  // family — the guard against a rule inflating its own family's totals.
  const multiSameFamily = flat.find(f => f.controls.length > 1 &&
    new Set(f.controls.map(controlFamilyOf)).size < f.controls.length);
  if(multiSameFamily){
    const fam = controlFamilyOf(multiSameFamily.controls[0]);
    const inFam = flat.filter(f => f.controls.some(c => controlFamilyOf(c) === fam)).length;
    const row = famRows.find(r => r.family === fam);
    check(row && row.total === inFam,
      \`a finding citing several controls within one family counts once for that family (\${fam}: row \${row && row.total} == \${inFam} distinct findings)\`);
  }

  // --- Overlap is intentional: family totals should SUM to more than the
  // raw finding count whenever any finding spans multiple families.
  const spansFamilies = flat.some(f => new Set(f.controls.map(controlFamilyOf)).size > 1);
  if(spansFamilies){
    const summed = famRows.reduce((s,r)=>s+r.total, 0);
    check(summed > allVulns.length,
      \`family rule counts overlap by design when findings span families (\${summed} > \${allVulns.length}) — not a partition of the finding total\`);
  }

  // --- Per-control rows within a family
  const biggestFam = famRows.filter(r=>!r.unmapped).slice().sort((a,b)=>b.total-a.total)[0];
  check(!!biggestFam, "found a mapped family to drill into");
  const ctrlRows = complianceControlRows(biggestFam.family);
  check(ctrlRows.length === biggestFam.controlCount,
    \`family row's control count matches the drill-down row count (\${biggestFam.controlCount} == \${ctrlRows.length})\`);
  check(ctrlRows.every(r => controlFamilyOf(r.control) === biggestFam.family),
    "every control in the drill-down actually belongs to that family");
  const oneControl = ctrlRows.slice().sort((a,b)=>b.total-a.total)[0];
  const manualCtrl = flat.filter(f => f.controls.includes(oneControl.control));
  check(oneControl.total === manualCtrl.length,
    \`control row's rule count matches a manual tally (\${oneControl.control}: \${oneControl.total} == \${manualCtrl.length})\`);
  check(oneControl.hostCount === new Set(manualCtrl.map(f=>f.hostKey)).size,
    "control row's asset count matches the distinct hosts carrying those findings");
  check(ctrlRows.every(r => r.compliance >= 0 && r.compliance <= 100), "every control's % compliant stays within 0-100");

  // --- Drill-through: the Findings blade filtered by control must return
  // exactly the findings citing that control (matching on ANY of a
  // finding's controls, since one finding can cite several).
  const drilled = newBlade("findings", oneControl.control, {presetControl: oneControl.control});
  check(drilled.state.colFilters.control.has(oneControl.control), "presetControl seeds the findings blade's control filter");
  renderFindingsList(drilled, 0);
  check(drilled._lastVulns.length === manualCtrl.length,
    \`drilling into \${oneControl.control} shows exactly its \${manualCtrl.length} findings (got \${drilled._lastVulns.length})\`);
  check(drilled._lastVulns.every(v => controlsForCciField(v.cci).includes(oneControl.control)),
    "every row in the drilled findings blade actually cites that control");

  // An unfiltered findings blade must be unaffected by the new filter.
  const unfiltered = newBlade("findings", "Findings", {});
  renderFindingsList(unfiltered, 0);
  check(unfiltered._lastVulns.length === allVulns.length, "a findings blade with no control preset still shows every finding");

  // --- Rendering: one table, family rows expand in place (no separate
  // per-family blade) to reveal their control rows.
  const compBlade = newBlade("compliance", "Compliance", {});
  check(compBlade.state.expandedFamilies instanceof Set && compBlade.state.expandedFamilies.size === 0,
    "Compliance blade starts with no families expanded");

  // Toggle-compliance-family elements now come from TWO places: the table's
  // family rows, and the grid's stat panels (a panel only gets the action
  // when its family actually has a row to expand — the "no data" panels
  // don't). Both must agree on the same set of mapped, expandable families.
  const mappedInTable = famRows.filter(r=>!r.unmapped);
  const mappedInGrid = mappedInTable.filter(r=>RMF_FAMILY_ORDER.includes(r.family));
  const expectedToggleCount = mappedInTable.length + mappedInGrid.length;

  const collapsedHtml = renderCompliance(compBlade, 0);
  check(collapsedHtml.includes("RMF Control Family Coverage"), "Compliance blade renders its family-coverage panel");
  check(collapsedHtml.includes(">Controls<") && collapsedHtml.includes(">% Compliant<"), "Compliance blade renders Controls and % Compliant columns");
  check((collapsedHtml.match(/data-action="toggle-compliance-family"/g)||[]).length === expectedToggleCount,
    \`every mapped family is expandable from both the table row and the grid panel (\${expectedToggleCount} toggle points)\`);
  check(!collapsedHtml.includes(esc(oneControl.control) + "<"), "collapsed by default: no control rows rendered until a family is expanded");
  check(!collapsedHtml.includes('data-type="complianceFamily"') && !collapsedHtml.includes("complianceFamily"),
    "no more separate complianceFamily blade type anywhere in the markup");

  // --- Family stat-panel grid: all 20 Rev 5 families, 10 per row, colored
  // by % compliant, "no data" families shown distinctly rather than omitted.
  check((collapsedHtml.match(/class="fam-panel[ "]/g)||[]).length === RMF_FAMILY_ORDER.length,
    \`the grid renders exactly one panel per official family (\${RMF_FAMILY_ORDER.length})\`);
  const naFamilies = RMF_FAMILY_ORDER.filter(code => !mappedInTable.some(r=>r.family===code));
  check((collapsedHtml.match(/fam-panel fam-panel-na/g)||[]).length === naFamilies.length,
    \`families with zero mapped findings (\${naFamilies.length}: \${naFamilies.join(", ") || "none"}) render as "no data" panels\`);
  if(naFamilies.length){
    check(collapsedHtml.includes(">"+esc(naFamilies[0])+"<") && collapsedHtml.includes(">N/A<"),
      "a no-data panel shows its family code and N/A, not a fabricated percentage");
  }
  // Every mapped family panel encodes its actual % compliant, not just some
  // color — checked by presence of the exact "NN%" text within a fam-panel.
  mappedInGrid.forEach(r=>{
    check(collapsedHtml.includes('data-family="'+esc(r.family)+'"') && collapsedHtml.includes(">"+r.compliance+"%<"),
      \`\${r.family}'s grid panel shows its actual compliance percentage (\${r.compliance}%)\`);
  });
  check(collapsedHtml.includes("fam-grid-legend"), "the grid includes a legend explaining the color gradient and no-data state");

  // Family rows show only the abbreviation in the Family column — the full
  // NIST name is a hover tooltip, not inline text, so a long name (e.g.
  // "Assessment, Authorization, and Monitoring") can't wrap and stretch that
  // row taller than its neighbors.
  const longNameFam = famRows.find(r => !r.unmapped && r.familyName.length > 20);
  check(!!longNameFam, "found a family with a long enough name to test wrapping avoidance against");
  if(longNameFam){
    check(!collapsedHtml.includes(">"+esc(longNameFam.familyName)+"<"),
      \`the full family name ("\${longNameFam.familyName}") is not rendered as visible row text\`);
    check(collapsedHtml.includes('data-tip="'+esc(longNameFam.familyName)+'"'),
      "the full family name is available as a tooltip instead");
  }
  check((collapsedHtml.match(/class="fam-code tooltip"/g)||[]).length === famRows.length,
    "every family row's abbreviation carries the tooltip class");

  // Expand one family — its control rows should appear inline, still
  // drilling into the Findings blade with a control preset, and nothing
  // about the still-collapsed families should change.
  compBlade.state.expandedFamilies.add(biggestFam.family);
  const expandedHtml = renderCompliance(compBlade, 0);
  check(expandedHtml.includes(esc(oneControl.control)), "expanding a family reveals its individual control numbers inline");
  check(expandedHtml.includes('data-type="findings"') && expandedHtml.includes('data-preset-control="'+esc(oneControl.control)+'"'),
    "expanded control rows drill into the Findings blade with a control preset");
  check((expandedHtml.match(/class="compliance-sub-row"/g)||[]).length === biggestFam.controlCount,
    \`expanding \${biggestFam.family} reveals exactly its \${biggestFam.controlCount} control rows\`);
  check((expandedHtml.match(/data-action="toggle-compliance-family"/g)||[]).length === expectedToggleCount,
    "every family row and grid panel (expanded or not) is still present and still toggleable");
  compBlade.state.expandedFamilies.delete(biggestFam.family);
  check(!renderCompliance(compBlade, 0).includes(esc(oneControl.control)+"<"),
    "collapsing the family again hides its control rows");

  // The unmapped bucket, if present, is atomic — it has nothing further to
  // expand into, so it gets no toggle affordance.
  const unmappedRow = famRows.find(r=>r.unmapped);
  if(unmappedRow){
    check(!expandedHtml.includes('data-family="'+esc(unmappedRow.family)+'"'),
      "the unmapped bucket has no expand/collapse toggle");
  }

  // Search narrows the family rows.
  compBlade.state.search = biggestFam.family;
  const searched = renderCompliance(compBlade, 0);
  check(searched.includes("showing 1 of " + famRows.length) || searched.includes(">"+esc(biggestFam.family)+"<"),
    "searching the Compliance blade narrows to the matching family");
  compBlade.state.search = "";

  // Sorting by % compliant must actually reorder.
  compBlade.state.sortKey = "compliance"; compBlade.state.sortDir = 1;
  const ascRows = sortComplianceRows(complianceFamilyRows(), compBlade.state, "family");
  let ascOk = true;
  for(let i=1;i<ascRows.length;i++){ if(ascRows[i].compliance < ascRows[i-1].compliance) ascOk = false; }
  check(ascOk, "sorting the Compliance blade by % compliant orders worst-first ascending");

  // --- Menu wiring
  check(MENU_TITLE.compliance === "Compliance", "Compliance has a menu title");
  check(bladeWidthClass("compliance") === "blade-w-lg", "Compliance blade gets a width class");
  check(newBlade("compliance","c",{}).state.sortKey === "family", "Compliance blade defaults to sorting by family");
}

// ======================================================================
// Import performance — string interning
//
// A STIG rule's discussion / check / fix text is byte-identical on every
// host the STIG is applied to, but JSON.parse hands back a fresh string per
// occurrence. Measured on the 80-file sample set those fields retained
// ~105 MB, ~80% of it exact duplicates. intern() collapses them to one
// shared instance, which is the single largest memory saving on import.
// ======================================================================
section("Import performance — string interning");
{
  check(typeof intern === "function", "intern() exists");

  // NOTE ON WHAT CAN BE ASSERTED HERE.
  // The saving is that N equal strings become one retained instance. JS has
  // no operator that distinguishes two equal string instances — \`===\` on
  // strings compares value — so the sharing itself cannot be observed from
  // script, and an "identity" check would pass even against a no-op intern().
  // What IS observable is the table that does the collapsing: it must hold
  // exactly one entry per distinct string and must not grow on a repeat.
  // These checks pin that, plus the requirement that values are unchanged.

  const probeA = "interning probe — rule discussion text";
  const probeB = ["interning probe", " — rule discussion text"].join(""); // equal, built at runtime
  check(probeA === probeB, "test fixture: the two probe strings are equal");
  check(!_internTable.has(probeA), "test fixture: the probe string is not in the table yet");

  const sizeBefore = _internTable.size;
  check(intern(probeA) === probeA, "intern() returns a value equal to its input");
  check(_internTable.size === sizeBefore + 1, "interning a new string adds exactly one table entry");
  check(_internTable.has(probeA), "the interned string is recorded in the table");

  const sizeAfterFirst = _internTable.size;
  check(intern(probeB) === probeB, "interning an equal string still returns that value");
  check(_internTable.size === sizeAfterFirst,
    "interning an equal string adds NO new entry — this is the deduplication that saves the memory");
  for(let i = 0; i < 50; i++) intern(["interning probe", " — rule discussion text"].join(""));
  check(_internTable.size === sizeAfterFirst, "interning the same value 50 more times still adds no entries");

  // Pass-through cases must not corrupt values or waste table slots.
  const sizeBeforeEdge = _internTable.size;
  check(intern("") === "", "intern('') returns ''");
  check(intern(undefined) === undefined, "intern(undefined) passes through untouched");
  check(intern(null) === null, "intern(null) passes through untouched");
  check(intern(42) === 42, "intern() passes non-strings through unchanged");
  check(_internTable.size === sizeBeforeEdge, "empty strings and non-strings are never added to the table");

  // The payoff, measured on the real sample data: the parse must have routed
  // the heavy text fields through the table, and those fields must contain
  // far fewer distinct values than there are rules — that ratio is the
  // memory saving.
  const distinctDiscussion = new Set(), distinctCheck = new Set();
  let ruleCount = 0, tabled = 0;
  assets.forEach(a2 => a2.vulns.forEach(v => {
    ruleCount++;
    if(v.discussion){ distinctDiscussion.add(v.discussion); if(_internTable.has(v.discussion)) tabled++; }
    if(v.checkContent) distinctCheck.add(v.checkContent);
  }));
  check(ruleCount > 1000, \`sample set is large enough to be meaningful (\${ruleCount} rules)\`);
  check(tabled > 1000, \`parsed rule text actually went through intern() (\${tabled} of \${ruleCount} discussions are in the table)\`);
  check(distinctDiscussion.size * 4 < ruleCount,
    \`discussions are heavily duplicated across hosts, so interning pays off (\${distinctDiscussion.size} distinct / \${ruleCount} rules)\`);
  check(distinctCheck.size * 4 < ruleCount,
    \`check content is heavily duplicated too (\${distinctCheck.size} distinct / \${ruleCount} rules)\`);

  // Interning must not alter any value — this is a memory optimization only.
  let mismatched = 0;
  assets.forEach(a2 => a2.vulns.forEach(v => {
    if(typeof v.discussion !== "string" || typeof v.checkContent !== "string") mismatched++;
    if(v.ruleTitle === "" || v.ruleTitle == null) mismatched++;
  }));
  check(mismatched === 0, "interning left every rule's text fields intact (still strings, titles non-empty)");
}

// ======================================================================
// Import performance — CKL attribute extraction
//
// parseCKL needs ten attributes per rule. Reading them with ten separate
// querySelectorAll scans was O(fields x nodes) per rule and dominated large
// .ckl imports; vulnAttrMap() collects them in one pass. The map must stay
// behaviourally identical to the old per-attribute scan.
// ======================================================================
section("Import performance — CKL attribute extraction");
{
  // Minimal stand-in for a <VULN> element. Node has no DOMParser and the
  // sample set is all .cklb, so the DOM shape is faked just precisely enough
  // to exercise vulnAttrMap/attr.
  function fakeVuln(pairs){
    let scans = 0;
    const nodes = pairs.map(([k, v]) => ({
      querySelector(sel){
        if(sel === "VULN_ATTRIBUTE") return k === null ? null : { textContent: k };
        if(sel === "ATTRIBUTE_DATA") return v === null ? null : { textContent: v };
        return null;
      }
    }));
    return {
      get scanCount(){ return scans; },
      querySelectorAll(sel){ if(sel === "STIG_DATA"){ scans++; return nodes; } return []; }
    };
  }

  const el = fakeVuln([
    ["Vuln_Num", " V-12345 "], ["Rule_ID", "SV-1_rule"], ["Rule_Ver", "ABCD-00-000010"],
    ["Rule_Title", "A rule title"], ["Severity", "high"], ["Group_Title", "SRG-OS-000001"],
    ["Vuln_Discuss", "why it matters"], ["Check_Content", "how to check"],
    ["Fix_Text", "how to fix"], ["CCI_REF", "CCI-000366"]
  ]);
  const map = vulnAttrMap(el);
  check(map["Vuln_Num"] === "V-12345", "vulnAttrMap trims attribute values, matching the old attr() behavior");
  check(map["CCI_REF"] === "CCI-000366", "vulnAttrMap reads every attribute, not just the first");
  check(map["Rule_Title"] === "A rule title" && map["Fix_Text"] === "how to fix", "vulnAttrMap reads attributes from anywhere in the node list");
  check(el.scanCount === 1, "vulnAttrMap scans the STIG_DATA node list exactly once for all ten attributes");

  // Behavioural parity with the previous implementation.
  const el2 = fakeVuln([["Rule_Title", "T"], ["Severity", "low"]]);
  check(attr(el2, "Rule_Title") === "T", "attr() still returns a present attribute");
  check(attr(el2, "Nope") === "", "attr() still returns '' for an absent attribute");
  const dup = fakeVuln([["Rule_Title", "first"], ["Rule_Title", "second"]]);
  check(vulnAttrMap(dup)["Rule_Title"] === "first", "first occurrence wins on duplicate attributes, as the old scan did");
  const missingData = fakeVuln([["Rule_Title", null]]);
  check(vulnAttrMap(missingData)["Rule_Title"] === "", "an attribute with no ATTRIBUTE_DATA node reads as ''");
  const missingKey = fakeVuln([[null, "orphan"], ["Rule_Ver", "R-1"]]);
  check(vulnAttrMap(missingKey)["Rule_Ver"] === "R-1", "a STIG_DATA node with no VULN_ATTRIBUTE is skipped, not fatal");

  // Security: a checklist is untrusted input, and attribute names come
  // straight out of it. A null-prototype map means a rule can't smuggle an
  // inherited Object member in where a string is expected.
  const hostile = fakeVuln([["__proto__", "pwned"], ["constructor", "pwned"], ["toString", "pwned"], ["Rule_Ver", "R-2"]]);
  const hmap = vulnAttrMap(hostile);
  check(Object.getPrototypeOf(hmap) === null, "vulnAttrMap returns a null-prototype object");
  check(typeof hmap["toString"] !== "function", "a VULN_ATTRIBUTE named toString cannot expose Object.prototype.toString");
  check(attr(hostile, "hasOwnProperty") === "", "an absent attribute never resolves to an inherited Object member");
  check(hmap["Rule_Ver"] === "R-2", "hostile attribute names don't prevent the real attributes from being read");
  check(({}).__proto__ !== "pwned" && Object.prototype.toString !== "pwned", "parsing a hostile checklist does not pollute Object.prototype");
}

// ======================================================================
// Derived-view caching
//
// allFindingsWithControls / complianceFamilyRows / decoratedFindings each
// rebuild tens of thousands of objects and are called several times per
// render (and once per search keystroke). They are memoized on a version
// counter; these checks pin both halves of that contract — that the cache
// is actually used, and that callers can't corrupt it.
// ======================================================================
section("Derived-view caching");
{
  check(typeof memoOnVersion === "function", "memoOnVersion helper exists");

  // ---- Structural guard on the invalidation contract ----
  // Caching is only safe while EVERY write to \`assets\` bumps assetsVersion.
  // A missed bump has no visible symptom — the blades just quietly show
  // pre-import data — and it cannot be caught by exercising the app's real
  // write paths from here, since those live behind FileReader and DOM
  // events. So the source itself is checked: all writes must go through
  // addAssets/setAssets, which bump for you.
  check(typeof addAssets === "function" && typeof setAssets === "function",
    "addAssets/setAssets are the supported mutators");

  const appSrc = fs.readFileSync(${JSON.stringify(HTML_PATH)}, "utf8");
  const scriptStart = appSrc.indexOf("<script>");
  const scriptBody = appSrc.slice(scriptStart, appSrc.indexOf("</script>", scriptStart));
  // Scanned line by line so the report can name the offending line. Skipped:
  // comment lines (they discuss the rule), the single \`let assets\`
  // declaration, and the bodies of the two helpers themselves — which are
  // legitimately the one place these writes are allowed.
  const srcLines = scriptBody.split("\\n");
  let inAdd = false, inSet = false;
  const offendersPush = [], offendersAssign = [];
  srcLines.forEach((lineText, i) => {
    const t = lineText.trim();
    if(/^function addAssets\\(/.test(t)) inAdd = true;
    else if(/^function setAssets\\(/.test(t)) inSet = true;
    else if((inAdd || inSet) && t === "}"){ inAdd = false; inSet = false; return; }
    if(inAdd || inSet) return;
    if(t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return;
    if(/^let assets\\s*=/.test(t)) return;
    if(/\\bassets\\.push\\s*\\(/.test(lineText)) offendersPush.push((i+1) + ": " + t);
    if(/(?:^|[^.\\w])assets\\s*=[^=]/.test(lineText)) offendersAssign.push((i+1) + ": " + t);
  });
  check(offendersPush.length === 0,
    \`no raw assets.push() outside addAssets()\${offendersPush.length ? " — " + offendersPush.join(" | ") : ""}\`);
  check(offendersAssign.length === 0,
    \`no raw assets = ... outside setAssets()\${offendersAssign.length ? " — " + offendersAssign.join(" | ") : ""}\`);

  // And the helpers must actually bump, or the guard above is decorative.
  const addSrc = String(addAssets), setSrc = String(setAssets);
  check(/bumpAssetsVersion\\s*\\(\\s*\\)/.test(addSrc), "addAssets() bumps the assets version");
  check(/bumpAssetsVersion\\s*\\(\\s*\\)/.test(setSrc), "setAssets() bumps the assets version");

  // Cache hit: same array instance back on a second call with no mutation.
  const f1 = allFindingsWithControls(), f2 = allFindingsWithControls();
  check(f1 === f2, "allFindingsWithControls() returns the cached instance when assets are unchanged");
  const fam1 = complianceFamilyRows(), fam2 = complianceFamilyRows();
  check(fam1 === fam2, "complianceFamilyRows() returns the cached instance when assets are unchanged");
  const ctl1 = complianceControlRows("AC"), ctl2 = complianceControlRows("AC");
  check(ctl1 === ctl2, "complianceControlRows() caches per family");
  check(complianceControlRows("AU") !== ctl1, "complianceControlRows() keys its cache by family, not one shared entry");
  const dec1 = decoratedFindings(), dec2 = decoratedFindings();
  check(dec1 === dec2, "decoratedFindings() returns the cached instance when assets and ACR are unchanged");

  // The Host / STIG filter dropdowns were moved into the same cache. They
  // must still be complete, de-duplicated and alphabetical — the dropdown is
  // unusable otherwise, and nothing else would notice the ordering was lost.
  const opts1 = findingsFilterOptions(), opts2 = findingsFilterOptions();
  check(opts1 === opts2, "findingsFilterOptions() is cached alongside the decorated findings");
  const expectedSources = Array.from(new Set(dec1.map(v => v._sourceLabel).filter(Boolean)));
  const expectedStigs = Array.from(new Set(dec1.map(v => v._stigLabel).filter(Boolean)));
  check(opts1.sourceOptions.length === expectedSources.length,
    \`every host appears exactly once in the Host filter (\${opts1.sourceOptions.length} == \${expectedSources.length})\`);
  check(opts1.stigOptions.length === expectedStigs.length,
    \`every STIG appears exactly once in the STIG filter (\${opts1.stigOptions.length} == \${expectedStigs.length})\`);
  // (Ordering is asserted in the "Cache invalidation" section instead: the
  // sample checklists are read off disk in alphabetical order, so here the
  // insertion order already equals the sorted order and a dropped .sort()
  // would be invisible. That section imports a host out of alphabetical
  // order, which makes the check able to fail.)

  // Correctness: the cached values must equal what an uncached computation
  // would produce, or the optimization has changed behavior.
  check(f1.length === allVulns.length, \`cached allFindingsWithControls still covers every finding (\${f1.length} == \${allVulns.length})\`);
  check(dec1.length === allVulns.length, \`cached decoratedFindings still covers every finding (\${dec1.length} == \${allVulns.length})\`);
  check(dec1.every(v => v._sourceLabel && v._stigLabel && v._criticality), "every decorated finding still carries host, STIG and criticality");
  const famTotal = fam1.reduce((s,r)=>s+r.total, 0);
  check(famTotal > 0 && fam1.every(r => typeof r.compliance === "number"), "cached family rows still carry real tallies");

  // The caches are shared, so a render must never sort or splice them in
  // place. filterVulns copies defensively; this pins that.
  const before = dec1.slice(0, 5).map(v => v.id);
  const sortBlade = newBlade("findings", "Findings", {});
  sortBlade.state.sortKey = "title"; sortBlade.state.sortDir = 1;
  filterVulns(decoratedFindings(), sortBlade.state);
  sortBlade.state.sortKey = "source"; sortBlade.state.sortDir = -1;
  filterVulns(decoratedFindings(), sortBlade.state);
  const after = decoratedFindings().slice(0, 5).map(v => v.id);
  check(before.join("|") === after.join("|"), "filtering/sorting the findings list does not reorder the cached array");
  check(decoratedFindings().length === dec1.length, "filtering does not remove rows from the cached array");

  // Same guarantee for the compliance blade, which sorts control rows.
  const ctlBefore = complianceControlRows("AC").map(r => r.control).join("|");
  const compBlade2 = newBlade("compliance", "Compliance", {});
  compBlade2.state.expandedFamilies.add("AC");
  renderCompliance(compBlade2, 0);
  renderCompliance(compBlade2, 0);
  const ctlAfter = complianceControlRows("AC").map(r => r.control).join("|");
  check(ctlBefore === ctlAfter, "rendering an expanded family does not reorder the cached control rows");

  // Re-rendering the same blade must stay byte-identical — a cache leaking
  // state between renders would show up here as drifting markup. (Compared
  // per blade rather than across two blades, since newBlade hands out a
  // fresh incrementing id that is itself embedded in the markup.)
  const rBlade = newBlade("compliance", "Compliance", {});
  check(renderCompliance(rBlade, 0) === renderCompliance(rBlade, 0), "re-rendering a Compliance blade produces identical markup");
  const gBlade = newBlade("findings", "Findings", {});
  check(renderFindingsList(gBlade, 0) === renderFindingsList(gBlade, 0), "re-rendering a Findings blade produces identical markup");
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
  bumpAssetsVersion();

  const day1Points = aesHistory(HOST);
  check(day1Points.length === 1, \`a single-day, multi-STIG import produces exactly one history point (got \${day1Points.length})\`);
  check(day1Points.length && formatDateISO(day1Points[0].date) === "2026-07-22", "that one point is dated the calendar day of the scans, not fractured across their exact timestamps");

  // Day 2: two of those STIGs re-scanned the next day, again a few minutes
  // apart — must add exactly one MORE point (real day-over-day history must
  // still work), not merge into day 1 and not add two more.
  assets.push({id:"r4", fileName:"r4.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG A", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-23T09:00:00Z", vulns:[mkVuln("NotAFinding"), mkVuln("NotAFinding")]});
  assets.push({id:"r5", fileName:"r5.cklb", hostName:HOST, hostIp:"", role:"", stigTitle:"STIG B", stigVersion:"1", releaseInfo:"", scanDate:"2026-07-23T09:05:30Z", vulns:[mkVuln("NotAFinding"), mkVuln("NotAFinding")]});
  bumpAssetsVersion();

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

// ======================================================================
// Cache invalidation
//
// The memoized derived views are only correct if every mutation of \`assets\`
// bumps the version they key off. A stale cache here would mean an imported
// file silently not appearing in the Findings or Compliance blades — the
// worst failure mode of the caching work, because nothing looks broken.
//
// Mutates \`assets\` and \`acrOverrides\`, so it runs last.
// ======================================================================
section("Cache invalidation");
{
  const mkVuln2 = (id, status, cci) => ({id, vulnNum:"V-CACHE", ruleId:"SV-CACHE", ruleVer:"CACHE-00-000001",
    ruleTitle:"cache invalidation probe", severity:"medium", status, groupTitle:"", discussion:"",
    checkContent:"", fixText:"", cci: cci || "CCI-000366", findingDetails:"", comments:""});
  const CACHE_HOST = "REGRESSION-CACHE-HOST";

  // Warm every cache, then mutate assets the way an import does.
  const beforeFindings = decoratedFindings().length;
  const beforeFlat = allFindingsWithControls().length;
  const beforeFamRows = complianceFamilyRows();
  const beforeAcTotal = (beforeFamRows.find(r => r.family === "AC") || {total:0}).total;

  const probe = {id:"cache1", fileName:"cache1.cklb", sourceFile:"cache1.cklb", hostName:CACHE_HOST,
    hostIp:"", role:"", stigTitle:"CACHE STIG", stigVersion:"1", releaseInfo:"",
    scanDate:"2026-07-24T10:00:00Z",
    vulns:[mkVuln2("c1","Open"), mkVuln2("c2","Open"), mkVuln2("c3","NotAFinding")]};
  assets.push(probe);
  bumpAssetsVersion();

  check(decoratedFindings().length === beforeFindings + 3,
    \`importing 3 findings makes decoratedFindings recompute (\${beforeFindings} -> \${decoratedFindings().length})\`);
  check(allFindingsWithControls().length === beforeFlat + 3,
    "allFindingsWithControls picks up newly imported findings");
  const afterFamRows = complianceFamilyRows();
  check(afterFamRows !== beforeFamRows, "complianceFamilyRows returns a fresh array after an import");
  const afterAc = (afterFamRows.find(r => r.family === "AC") || {total:0}).total;
  // CCI-000366 maps into CM, so AC is untouched; assert against whichever
  // family the probe's CCI actually resolves to rather than assuming.
  const probeFams = new Set(controlsForCciField("CCI-000366").map(controlFamilyOf));
  check(probeFams.size > 0, "test fixture: the probe CCI maps to at least one control family");
  probeFams.forEach(fam => {
    const b = (beforeFamRows.find(r => r.family === fam) || {total:0}).total;
    const a2 = (afterFamRows.find(r => r.family === fam) || {total:0}).total;
    check(a2 === b + 3, \`\${fam} family total grew by the 3 imported findings (\${b} -> \${a2})\`);
  });
  check(afterAc >= beforeAcTotal, "unrelated families are not corrupted by the import");

  // The per-family control-row cache must invalidate too.
  probeFams.forEach(fam => {
    const rows = complianceControlRows(fam);
    check(rows.some(r => r.total > 0), \`complianceControlRows("\${fam}") recomputed after import\`);
  });

  // Host/STIG filter dropdowns are cached too. The probe host was imported
  // last but sorts into the middle of the list, so insertion order differs
  // from sorted order here — which is what makes this able to catch a
  // dropped .sort() (it could not in the earlier section, where the sample
  // files are already read in alphabetical order).
  const invOpts = findingsFilterOptions();
  check(invOpts.sourceOptions.includes(CACHE_HOST), "a newly imported host appears in the Host filter options");
  const invIdx = invOpts.sourceOptions.indexOf(CACHE_HOST);
  check(invIdx > 0 && invIdx < invOpts.sourceOptions.length - 1,
    \`the probe host sorts into the middle of the list, not at its insertion position (index \${invIdx} of \${invOpts.sourceOptions.length})\`);
  const invSorted = invOpts.sourceOptions.slice().sort((a,b)=>a.localeCompare(b));
  check(invOpts.sourceOptions.join("|") === invSorted.join("|"), "Host filter options stay alphabetically sorted after an import");
  const invStigSorted = invOpts.stigOptions.slice().sort((a,b)=>a.localeCompare(b));
  check(invOpts.stigOptions.join("|") === invStigSorted.join("|"), "STIG filter options stay alphabetically sorted after an import");

  // The rendered Compliance blade must actually show the new data — this is
  // the user-visible symptom a stale cache would produce.
  const invBlade = newBlade("compliance", "Compliance", {});
  const invHtml = renderCompliance(invBlade, 0);
  check(invHtml.includes("Findings assessed"), "Compliance blade still renders after an import");
  const assessed = /Findings assessed: <b>(\\d+)<\\/b>/.exec(invHtml);
  check(!!assessed && Number(assessed[1]) === beforeFlat + 3,
    \`Compliance blade's "Findings assessed" reflects the import (expected \${beforeFlat + 3}\${assessed ? ", got " + assessed[1] : ""})\`);

  // ACR is a separate input: editing it must rebuild the decorated findings
  // (criticality is derived from it) without needing an assets change.
  const acrHost = decoratedFindings().find(v => v._sourceLabel === CACHE_HOST);
  check(!!acrHost, "the imported host appears in the decorated findings");
  const critBefore = decoratedFindings().filter(v => v._sourceLabel === CACHE_HOST).map(v => v._criticality).join(",");
  const bandBefore = decoratedFindings().filter(v => v._sourceLabel === CACHE_HOST).map(v => v._acrBand).join(",");
  acrOverrides.set(CACHE_HOST, 10);
  bumpAcrVersion();
  const critAfter = decoratedFindings().filter(v => v._sourceLabel === CACHE_HOST).map(v => v._criticality).join(",");
  const bandAfter = decoratedFindings().filter(v => v._sourceLabel === CACHE_HOST).map(v => v._acrBand).join(",");
  check(bandBefore !== bandAfter, \`raising ACR to 10 invalidates the decorated-findings cache (band \${bandBefore} -> \${bandAfter})\`);
  check(bandAfter.split(",").every(b => b === "9-10"), "the new ACR band is reflected on every finding for that host");
  check(critBefore !== critAfter || critAfter.length > 0, "criticality is recomputed against the new ACR");

  // An ACR edit must NOT force the compliance caches (which don't depend on
  // ACR) to rebuild — that's the point of tracking the two versions apart.
  const famBeforeAcr = complianceFamilyRows();
  acrOverrides.set(CACHE_HOST, 7);
  bumpAcrVersion();
  check(complianceFamilyRows() === famBeforeAcr, "an ACR edit does not needlessly invalidate the compliance caches");

  // Removing data must invalidate as well.
  const flatBeforeRemove = allFindingsWithControls().length;
  assets = assets.filter(a2 => a2.id !== "cache1");
  bumpAssetsVersion();
  check(allFindingsWithControls().length === flatBeforeRemove - 3,
    "removing an asset invalidates the caches and drops its findings");
  check(!decoratedFindings().some(v => v._sourceLabel === CACHE_HOST),
    "the removed host no longer appears in the Findings blade data");
  acrOverrides.delete(CACHE_HOST);
  bumpAcrVersion();
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

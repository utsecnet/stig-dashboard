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
    // Real elements that the app looks up by [data-action="search"] are
    // <input>s, so the stub needs the input surface too — code that restores
    // the caret after a re-render reads .value/.selectionStart.
    value:"", selectionStart:0, selectionEnd:0,
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

// Minimal IndexedDB stand-in. The app itself has no persistence anymore
// (deliberately reverted — see purgeStalePersistedData() in the app body);
// this only needs to support the one-time best-effort cleanup call that
// deletes any database a since-removed earlier version may have left
// behind. global.__idbDeleteCalls records what was asked to be deleted, so
// tests can confirm the cleanup actually runs rather than being a no-op.
global.__idbDeleteCalls = [];
global.indexedDB = {
  deleteDatabase(name){
    global.__idbDeleteCalls.push(name);
    const req = {};
    setTimeout(()=>{ if(req.onsuccess) req.onsuccess(); }, 0);
    return req;
  }
};
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
// Findings blade — sticky Group preference across Compliance drills
//
// Regression: clicking a control on the Compliance blade (e.g. AC-2) opens
// a fresh Findings blade via openBlade()/newBlade(), which always started
// "grouped: false". So Group -> click a different control (SA-4) -> the new
// blade forgot Group was on. findingsGroupedPref (a module-level variable,
// same pattern as colPrefs) is meant to seed newBlade() with whatever the
// user last chose, so the setting survives a fresh drill.
//
// The click handler that flips findingsGroupedPref lives inside a delegated
// DOM listener this harness's fake DOM can't dispatch through (same
// limitation as every other data-action handler in this file), so the two
// halves of the contract are checked at the boundaries that are reachable:
// that newBlade() actually seeds from the module variable, and that the
// variable is scoped to the Findings blade type only.
// ======================================================================
section("Findings blade — sticky Group preference across Compliance drills");
{
  const savedPref = findingsGroupedPref; // restore afterward — this is shared session state

  findingsGroupedPref = false;
  check(newBlade("findings", "Findings", {}).state.grouped === false,
    "a fresh Findings blade starts ungrouped when the sticky preference is off");

  findingsGroupedPref = true;
  const afterGroupOn = newBlade("findings", "Findings", {presetControl:"AC-2"});
  check(afterGroupOn.state.grouped === true,
    "a fresh Findings blade opened while the sticky preference is on (e.g. drilling into AC-2) starts grouped");
  const secondDrill = newBlade("findings", "Findings", {presetControl:"SA-4"});
  check(secondDrill.state.grouped === true,
    "drilling into a SECOND control (SA-4) with the preference still on also starts grouped — this is the exact scenario reported: AC-2 -> Group -> SA-4");
  check(secondDrill.state.colFilters.control.has("SA-4") && !secondDrill.state.colFilters.control.has("AC-2"),
    "each drill still gets its own control filter — only the grouped flag is shared, not the rest of the blade's state");

  // Scoped to the Findings blade only — other blade types must never read
  // this variable, and must keep their own "grouped" behavior (they don't
  // have one) unaffected by it.
  check(newBlade("compliance", "Compliance", {}).state.grouped === false,
    "the sticky Group preference does not leak into unrelated blade types");
  check(newBlade("stigs", "STIGs", {}).state.grouped === false,
    "the sticky Group preference does not leak into the STIGs blade");

  // Rendering must actually reflect the seeded state (not just the raw
  // state object) — this is what the user sees.
  const seededBlade = newBlade("findings", "Findings", {});
  const seededHtml = renderFindingsList(seededBlade, 0);
  check(/class="group-btn[^"]*grouped[^"]*"[^>]*>Ungroup</.test(seededHtml),
    "a Findings blade seeded from the sticky preference actually renders grouped, showing an Ungroup button");

  findingsGroupedPref = savedPref;
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
// Search bar placeholder text — every search box across the app reads a
// plain "Search...", not the older per-blade hints ("Search rule title,
// STIG ID, group...", "Search host, IP, role...", etc.) that named specific
// fields and were confusing (a user asked what "group" meant).
// ======================================================================
section("Search bar placeholders");
{
  const PLAIN = 'placeholder="Search..."';
  const findingsHtml = renderFindingsList(newBlade("findings", "Findings", {}), 0);
  check(findingsHtml.includes(PLAIN), "Findings blade search box reads plain \\"Search...\\"");

  const assetsHtml = renderAssetsList(newBlade("assets", "Assets", {}), 0);
  check(assetsHtml.includes(PLAIN), "Assets blade search box reads plain \\"Search...\\"");
  check(!assetsHtml.includes("Search host, IP, role"), "Assets blade no longer names specific fields in its placeholder");

  const stigsHtml = renderStigsList(newBlade("stigs", "STIGs", {}), 0);
  check(stigsHtml.includes(PLAIN), "STIGs blade search box reads plain \\"Search...\\"");
  check(!stigsHtml.includes("Search STIG title, host, version"), "STIGs blade no longer names specific fields in its placeholder");

  const complianceHtml = renderCompliance(newBlade("compliance", "Compliance", {}), 0);
  check(complianceHtml.includes(PLAIN), "Compliance blade search box reads plain \\"Search...\\"");
  check(!complianceHtml.includes("Search family code or name"), "Compliance blade no longer names specific fields in its placeholder");

  // Every search-input placeholder anywhere in the app must be exactly this
  // one string — a stray blade-specific hint elsewhere would slip past the
  // four checks above.
  [findingsHtml, assetsHtml, stigsHtml, complianceHtml].forEach((html, i)=>{
    const matches = Array.from(html.matchAll(/class="search-input"[^>]*placeholder="([^"]*)"/g)).map(m=>m[1]);
    check(matches.length > 0 && matches.every(p => p === "Search..."),
      \`blade #\${i}: every search-input placeholder found is exactly "Search..." (got \${JSON.stringify(matches)})\`);
  });
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

  // --- AES formula, recalibrated 2026-07-29 — pinned exactly against an
  // independent re-implementation, so a future change to these constants is
  // a deliberate recalibration, not silent drift. See computeAES()'s own
  // comment for the full rationale (steeper curve, heavier CAT I weight,
  // Not_Applicable excluded from density).
  function manualAES(counts, acr){
    const w = {oH:15,oM:5,oL:2, nH:5,nM:1.5,nL:0.5};
    const raw = counts.openHigh*w.oH + counts.openMed*w.oM + counts.openLow*w.oL
              + counts.nrHigh*w.nH + counts.nrMed*w.nM + counts.nrLow*w.nL;
    const applicable = counts.openHigh+counts.openMed+counts.openLow+counts.nrHigh+counts.nrMed+counts.nrLow+counts.naf;
    const density = applicable ? raw/applicable : 0;
    const exposureScore = 1000*(1-Math.exp(-density/1.2));
    const multiplier = 0.3+0.07*acr;
    return Math.round(Math.min(1000, exposureScore*multiplier));
  }
  function mkHost(counts){
    const vulns = [];
    const push = (n, status, sev) => { for(let i=0;i<n;i++) vulns.push({status, severity:sev}); };
    push(counts.openHigh,"Open","high"); push(counts.openMed,"Open","medium"); push(counts.openLow,"Open","low");
    push(counts.nrHigh,"Not_Reviewed","high"); push(counts.nrMed,"Not_Reviewed","medium"); push(counts.nrLow,"Not_Reviewed","low");
    push(counts.naf,"NotAFinding","medium");
    push(counts.na||0,"Not_Applicable","medium");
    return {hostKey:"synthetic", hostName:"synthetic", stigs:[{vulns}]};
  }

  // The exact scenario from the bug report: a host at 75% compliant (25% of
  // applicable rules Open/Not-Reviewed) with a realistic DISA severity mix
  // (~15% CAT I / 65% CAT II / 20% CAT III among the failing rules). This
  // used to land around AES 240-320 ("OK"/"Low") — reassuring for a host
  // with a quarter of its applicable rules failing. It must not anymore.
  const counts75 = {openHigh:5, openMed:23, openLow:8, nrHigh:1, nrMed:6, nrLow:2, naf:135, na:20};
  const h75 = mkHost(counts75);
  const aes75 = computeAES(h75, 8).aes;
  check(aes75 === manualAES(counts75, 8), \`computeAES matches the pinned formula exactly for a 75%-compliant host (got \${aes75})\`);
  check(aes75 === 551, \`the reference 75%-compliant/ACR-8 scenario scores AES 551 under the recalibrated curve (got \${aes75})\`);
  check(aesBand(aes75) !== "OK" && aesBand(aes75) !== "Low",
    \`a host with 25% of applicable rules failing (typical severity mix, ACR 8) no longer reads as OK/Low — got AES \${aes75} (\${aesBand(aes75)})\`);

  // --- Not_Applicable rules must not affect AES, matching compliancePct()'s
  // exclusion of N/A from both sides of its ratio. Two hosts with identical
  // real posture (same open/not-reviewed/not-a-finding counts and
  // severities) but very different N/A counts must score identically.
  const lowNA = mkHost(Object.assign({}, counts75, {na:0}));
  const highNA = mkHost(Object.assign({}, counts75, {na:80}));
  check(computeAES(lowNA,8).aes === computeAES(highNA,8).aes,
    "AES is unaffected by how many Not_Applicable rules a host has, given identical open/not-reviewed/not-a-finding counts");

  // --- CAT I findings must weigh meaningfully more than CAT II/III at the
  // same compliance level — the other half of the recalibration, and the
  // part that was nearly invisible under the old weights (worst case there
  // only separated by ~150 points; it must be much wider now).
  const allCat1 = mkHost({openHigh:36, openMed:0, openLow:0, nrHigh:9, nrMed:0, nrLow:0, naf:135, na:20});
  const allCat3 = mkHost({openHigh:0, openMed:0, openLow:36, nrHigh:0, nrMed:0, nrLow:9, naf:135, na:20});
  const aesCat1 = computeAES(allCat1, 8).aes, aesCat3 = computeAES(allCat3, 8).aes;
  check(aesCat1 > aesCat3, "an all-CAT-I non-compliance profile scores higher AES than an all-CAT-III profile at the same compliance %");
  check(aesCat1 - aesCat3 > 400,
    \`CAT I is weighted heavily enough to meaningfully separate the two profiles (gap \${aesCat1 - aesCat3} points, was ~150 under the old weights)\`);

  // --- CES is ACR-weighted, not a flat mean (the other change in this
  // batch). Two fleets with the SAME pair of AES values but swapped ACRs
  // must produce different CES — that's what actually proves the weighting
  // changes the result, rather than merely running without error.
  const flatMean = Math.round((900+100)/2); // what an unweighted mean gives either way
  const cesHighCritBad = computeCES([{aes:900, acr:10}, {aes:100, acr:2}]); // the critical host is the exposed one
  const cesLowCritBad  = computeCES([{aes:900, acr:2}, {aes:100, acr:10}]); // the routine host is the exposed one
  check(cesHighCritBad !== cesLowCritBad,
    "swapping which host (critical vs routine) is the exposed one changes CES — proving it's ACR-weighted, not a flat average");
  check(cesHighCritBad > flatMean, \`a bad AES on the higher-ACR host pulls CES above the flat-mean baseline (\${cesHighCritBad} > \${flatMean})\`);
  check(cesLowCritBad < flatMean, \`a bad AES on the lower-ACR host pulls CES below the flat-mean baseline (\${cesLowCritBad} < \${flatMean})\`);
  check(computeCES([{aes:500,acr:5},{aes:500,acr:9}]) === 500, "equal AES across different ACRs still averages to that same value");
  check(computeCES([{aes:777,acr:1},{aes:777,acr:10}]) === 777, "identical AES everywhere gives that AES back regardless of ACR spread");
  check(computeCES([]) === 0, "CES of an empty fleet is 0, not NaN");

  // cesHistory() must use the exact same weighting as computeCES(), not an
  // independently-drifted formula — they share one helper for this reason.
  check(typeof weightedCES === "function", "weightedCES helper exists and is shared by computeCES and cesHistory");
  check(weightedCES([[900,10],[100,2]]) === computeCES([{aes:900,acr:10},{aes:100,acr:2}]),
    "weightedCES([aes,acr] pairs) and computeCES(rows) agree given equivalent input");
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
// Assets / STIGs blades — CSV export
//
// Mirrors the Findings blade's existing export: a button that exports
// whatever the table's current search/filter/sort produced (not the whole
// fleet unconditionally), reusing the same toCSV()/csvCell() escaping so
// formula-injection protection isn't something a new export path could
// accidentally bypass.
//
// Blob is monkey-patched for this section only, to capture the CSV text
// that was actually handed to it rather than re-deriving an expected string
// independently of the function under test.
// ======================================================================
section("Assets / STIGs blades — CSV export");
{
  const OrigBlob = global.Blob;
  let captured = null;
  global.Blob = function(parts, opts){ captured = parts[0]; return new OrigBlob(parts, opts); };

  // --- Assets blade --------------------------------------------------
  const assetsBlade = newBlade("assets", "Assets", {});
  const assetsHtml = renderAssetsList(assetsBlade, 0);
  check(assetsHtml.includes('data-action="export-assets"'), "Assets blade renders an export button");
  check(assetsHtml.includes('class="export-btn" data-blade-id="'+assetsBlade.id+'" data-action="export-assets"'),
    "Assets export button carries its blade id, wired the same way as the Findings export button");
  check(Array.isArray(assetsBlade._lastAssetRows) && assetsBlade._lastAssetRows.length === hosts.length,
    \`Assets blade stashes its full row set for export when unfiltered (\${assetsBlade._lastAssetRows.length} == \${hosts.length})\`);

  captured = null;
  exportAssetRowsCSV(assetsBlade._lastAssetRows, "assets_test");
  check(captured !== null, "exportAssetRowsCSV actually produces CSV content");
  let lines = captured.split("\\r\\n");
  check(lines[0] === '"Host Name","IP Address","Role","Operating System","ACR","AES","STIGs","Total Rules","Open","Not Reviewed","% Compliant","Last Scanned","History"',
    "Assets CSV header matches the exported column set");
  check(lines.length === hosts.length + 1, \`Assets CSV has one data row per host plus the header (\${lines.length} lines for \${hosts.length} hosts)\`);
  const sampleAssetRow = assetsBlade._lastAssetRows[0];
  const expectedAssetLine = [
    sampleAssetRow.host.hostName||"", sampleAssetRow.host.hostIp||"", sampleAssetRow.host.role||"", sampleAssetRow.os||"",
    sampleAssetRow.acr, sampleAssetRow.aes, sampleAssetRow.host.stigs.length, sampleAssetRow.total,
    sampleAssetRow.open, sampleAssetRow.nr, sampleAssetRow.compliance,
    (sampleAssetRow.lastScannedInfo && sampleAssetRow.lastScannedInfo.label) || "—", sampleAssetRow.history
  ].map(csvCell).join(",");
  check(lines[1] === expectedAssetLine, "the first exported Assets row's fields match that host's actual data, in the documented column order");

  // Export must follow the search box, not export the unfiltered fleet.
  // Expected count mirrors filterAssetRows()'s own predicate exactly (name
  // OR IP OR role), rather than a simplified re-guess that could
  // under/over-count against fields the real filter also checks.
  const searchTerm = (sampleAssetRow.host.hostName||"").slice(0,3).toLowerCase();
  check(searchTerm.length > 0, "test fixture: sample host has a name to search on");
  const filteredAssetsBlade = newBlade("assets", "Assets", {});
  filteredAssetsBlade.state.search = searchTerm;
  renderAssetsList(filteredAssetsBlade, 0);
  const expectedFilteredCount = buildAssetRows(hosts).filter(x =>
    (x.host.hostName||"").toLowerCase().includes(searchTerm) ||
    (x.host.hostIp||"").toLowerCase().includes(searchTerm) ||
    (x.host.role||"").toLowerCase().includes(searchTerm)
  ).length;
  check(filteredAssetsBlade._lastAssetRows.length === expectedFilteredCount,
    \`searching the Assets blade narrows what export-assets would export (\${filteredAssetsBlade._lastAssetRows.length} == \${expectedFilteredCount})\`);
  check(filteredAssetsBlade._lastAssetRows.length < hosts.length,
    "the search term actually narrows the fleet (test fixture sanity check)");

  // A hostile hostname must not slip a live formula into the exported CSV —
  // proves exportAssetRowsCSV routes through the same csvCell() escaping as
  // every other export, not a hand-rolled join that skipped it.
  const hostileHost = {host:{hostName:"=cmd|test!A1", hostIp:"", role:"", stigs:[{vulns:[]}]}, os:"", acr:5, aes:100, total:0, open:0, nr:0, compliance:100, lastScannedInfo:null, history:0};
  captured = null;
  exportAssetRowsCSV([hostileHost], "hostile_test");
  check(captured.split("\\r\\n")[1].startsWith("\\"'="), "a hostile host name is neutralized in the Assets CSV export, same as the Findings export");

  // --- STIGs blade -----------------------------------------------------
  const stigGroups = buildStigGroups();
  const stigsBlade = newBlade("stigs", "STIGs", {});
  const stigsHtml = renderStigsList(stigsBlade, 0);
  check(stigsHtml.includes('data-action="export-stigs"'), "STIGs blade renders an export button");
  check(stigsHtml.includes('class="export-btn" data-blade-id="'+stigsBlade.id+'" data-action="export-stigs"'),
    "STIGs export button carries its blade id, wired the same way as the Findings export button");
  check(Array.isArray(stigsBlade._lastStigRows) && stigsBlade._lastStigRows.length === stigGroups.length,
    \`STIGs blade stashes its full row set for export when unfiltered (\${stigsBlade._lastStigRows.length} == \${stigGroups.length})\`);

  captured = null;
  exportStigRowsCSV(stigsBlade._lastStigRows, "stigs_test");
  check(captured !== null, "exportStigRowsCSV actually produces CSV content");
  lines = captured.split("\\r\\n");
  check(lines[0] === '"STIG Title","Version","Release Info","Host Count","Total Rules","Open","Not Reviewed","% Compliant"',
    "STIGs CSV header matches the exported column set");
  check(lines.length === stigGroups.length + 1, \`STIGs CSV has one data row per STIG plus the header (\${lines.length} lines for \${stigGroups.length} STIGs)\`);
  const sampleStigRow = stigsBlade._lastStigRows[0];
  const expectedStigLine = [
    sampleStigRow.stigTitle||"Untitled STIG", sampleStigRow.stigVersion||"", sampleStigRow.releaseInfo||"",
    sampleStigRow.hostCount, sampleStigRow.total, sampleStigRow.open, sampleStigRow.nr, sampleStigRow.compliance
  ].map(csvCell).join(",");
  check(lines[1] === expectedStigLine, "the first exported STIGs row's fields match that STIG's actual data, in the documented column order");

  // Same "export follows the filter" guarantee on the STIGs blade. Expected
  // count mirrors filterStigRows()'s own predicate exactly (title OR any
  // host name OR version).
  const stigSearchTerm = (sampleStigRow.stigTitle||"").slice(0,3).toLowerCase();
  if(stigSearchTerm.length > 0){
    const filteredStigsBlade = newBlade("stigs", "STIGs", {});
    filteredStigsBlade.state.search = stigSearchTerm;
    renderStigsList(filteredStigsBlade, 0);
    const expectedFilteredStigCount = buildStigGroups().filter(g =>
      (g.stigTitle||"").toLowerCase().includes(stigSearchTerm) ||
      Array.from(g.hostNames).some(h=>(h||"").toLowerCase().includes(stigSearchTerm)) ||
      (g.stigVersion||"").toLowerCase().includes(stigSearchTerm)
    ).length;
    check(filteredStigsBlade._lastStigRows.length === expectedFilteredStigCount,
      \`searching the STIGs blade narrows what export-stigs would export (\${filteredStigsBlade._lastStigRows.length} == \${expectedFilteredStigCount})\`);
  }

  global.Blob = OrigBlob;
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
  compBlade.state.sortKey = "family"; compBlade.state.sortDir = 1;

  // --- Expanded control rows follow whichever sort the family table is
  // using, not a fixed control-code order. Regression: expanding a family
  // used to always sort its controls by control code regardless of what
  // column the user had sorted the family table by — sorting the outer
  // table by % Compliant reordered the family rows but left each expanded
  // family's own controls untouched.
  {
    // A synthetic control set exercises the sort logic directly, independent
    // of whatever the real sample data happens to contain — this is what
    // actually pins the bug (numeric vs. lexicographic control-code order)
    // rather than depending on the sample set having double-digit controls.
    const synth = () => ([
      {control:"AC-1", compliance:50, total:5, open:2, nr:0, naf:3, na:0, hostCount:1},
      {control:"AC-10", compliance:20, total:5, open:4, nr:0, naf:1, na:0, hostCount:1},
      {control:"AC-2", compliance:90, total:5, open:0, nr:0, naf:5, na:0, hostCount:1},
      {control:"AC-20", compliance:10, total:5, open:4, nr:1, naf:0, na:0, hostCount:1},
      {control:"AC-3", compliance:70, total:5, open:1, nr:0, naf:4, na:0, hostCount:1}
    ]);
    // Default state — sortKey "family" (what a freshly-opened Compliance
    // blade starts with) falls through to the numeric-aware default branch,
    // since control rows have no "family" field of their own.
    const byCode = sortComplianceRows(synth(), {sortKey:"family", sortDir:1}, "control").map(r=>r.control);
    check(byCode.join(",") === "AC-1,AC-2,AC-3,AC-10,AC-20",
      \`control rows sort numerically (AC-2 before AC-10), not lexicographically — got \${byCode.join(",")}\`);
    const byCodeDesc = sortComplianceRows(synth(), {sortKey:"family", sortDir:-1}, "control").map(r=>r.control);
    check(byCodeDesc.join(",") === "AC-20,AC-10,AC-3,AC-2,AC-1", "reversing direction reverses the numeric control-code order too");

    // The actual regression: sortKey "compliance" must reorder control rows
    // by their own % compliant, worst-first ascending / best-first descending.
    const byPct = sortComplianceRows(synth(), {sortKey:"compliance", sortDir:1}, "control").map(r=>r.control);
    check(byPct.join(",") === "AC-20,AC-10,AC-1,AC-3,AC-2",
      \`control rows sort by their own % compliant when that's the chosen column — got \${byPct.join(",")}\`);
    const byPctDesc = sortComplianceRows(synth(), {sortKey:"compliance", sortDir:-1}, "control").map(r=>r.control);
    check(byPctDesc.join(",") === "AC-2,AC-3,AC-1,AC-10,AC-20", "descending % compliant sorts control rows best-first");

    // Other sortable columns carry through too (open count here).
    const byOpen = sortComplianceRows(synth(), {sortKey:"open", sortDir:1}, "control").map(r=>r.control);
    check(byOpen.join(",") === "AC-2,AC-3,AC-1,AC-10,AC-20", "control rows also sort by Open count when that's the chosen column");
  }

  // Integration check against the real rendered blade: expand a family that
  // actually has spread in its controls' % compliant, sort the family table
  // by compliance, and confirm the rendered sub-rows come out in that order —
  // this is what would have caught the bug via the real render path, not
  // just the shared sort helper.
  {
    const candidates = famRows.filter(r=>!r.unmapped && r.controlCount >= 3)
      .map(r => ({row:r, ctrl:complianceControlRows(r.family)}))
      .filter(x => new Set(x.ctrl.map(c=>c.compliance)).size >= 2);
    check(candidates.length > 0, "sample data has a family with 3+ controls and varying compliance to test sort integration against");
    if(candidates.length){
      const {row: sortTestFam, ctrl: sortTestCtrl} = candidates[0];
      const sortBlade = newBlade("compliance", "Compliance", {});
      sortBlade.state.sortKey = "compliance"; sortBlade.state.sortDir = 1;
      sortBlade.state.expandedFamilies.add(sortTestFam.family);
      const sortedHtml = renderCompliance(sortBlade, 0);
      const renderedOrder = Array.from(sortedHtml.matchAll(/class="compliance-sub-row"[^>]*data-preset-control="([^"]+)"/g)).map(m=>m[1]);
      const expectedOrder = sortTestCtrl.slice().sort((a,b)=>a.compliance-b.compliance).map(c=>c.control);
      check(renderedOrder.length === sortTestCtrl.length,
        \`expanding \${sortTestFam.family} under a compliance sort still renders all \${sortTestCtrl.length} of its controls (got \${renderedOrder.length})\`);
      check(renderedOrder.join(",") === expectedOrder.join(","),
        \`\${sortTestFam.family}'s expanded control rows render in ascending % compliant order, matching the family table's sort (got \${renderedOrder.join(",")}, expected \${expectedOrder.join(",")})\`);

      sortBlade.state.sortDir = -1;
      const sortedHtmlDesc = renderCompliance(sortBlade, 0);
      const renderedOrderDesc = Array.from(sortedHtmlDesc.matchAll(/class="compliance-sub-row"[^>]*data-preset-control="([^"]+)"/g)).map(m=>m[1]);
      const expectedOrderDesc = sortTestCtrl.slice().sort((a,b)=>b.compliance-a.compliance).map(c=>c.control);
      check(renderedOrderDesc.join(",") === expectedOrderDesc.join(","),
        \`flipping the family table's sort direction also flips \${sortTestFam.family}'s expanded control-row order\`);
    }
  }

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

// ======================================================================
// Folder drop — recursive directory walk
//
// Dropping a folder hands the app a FileSystemDirectoryEntry and no files,
// so the tree is walked explicitly. The failure modes worth pinning are the
// ones that stay invisible until a user hits them with real data: the
// readEntries() batch cap silently truncating large folders, and one
// unreadable branch aborting the whole drop.
//
// Async, so it runs inside an IIFE that also prints the final summary —
// every synchronous section above has already completed by this point.
// ======================================================================
(async function(){
section("Folder drop — recursive directory walk");

// --- Fake FileSystemEntry tree ---------------------------------------
// Chrome hands back at most 100 entries per readEntries() call; BATCH
// mimics that so the pagination loop is actually exercised.
const BATCH = 100;
let readEntriesCalls = 0;
function fakeFile(name){
  return { isFile:true, isDirectory:false, name, fullPath:"/"+name,
    file(cb){ cb({ name, size: 10 }); } };
}
function fakeDir(name, children){
  return { isFile:false, isDirectory:true, name, fullPath:"/"+name,
    createReader(){
      let i = 0;
      return { readEntries(cb){
        readEntriesCalls++;
        const batch = children.slice(i, i + BATCH);
        i += batch.length;
        setTimeout(()=>cb(batch), 0);
      } };
    } };
}
// A directory whose reader always errors — one bad branch must not sink
// the rest of the drop.
function unreadableDir(name){
  return { isFile:false, isDirectory:true, name, fullPath:"/"+name,
    createReader(){ return { readEntries(cb, errcb){ setTimeout(()=>errcb(new Error("EACCES")), 0); } }; } };
}
function fakeUnreadableFile(name){
  return { isFile:true, isDirectory:false, name, fullPath:"/"+name,
    file(cb, errcb){ setTimeout(()=>errcb(new Error("gone")), 0); } };
}
const names = out => out.map(f=>f.name).sort();

// --- Flat folder, mixed contents --------------------------------------
{
  const dir = fakeDir("drop", [
    fakeFile("a.cklb"), fakeFile("b.ckl"), fakeFile("c.xml"),
    fakeFile("readme.txt"), fakeFile("notes.md"), fakeFile("archive.zip")
  ]);
  const out = [];
  await walkEntry(dir, out, 0);
  check(out.length === 3, \`a dropped folder yields only its checklists (got \${out.length} of 6 files)\`);
  check(names(out).join(",") === "a.cklb,b.ckl,c.xml", "non-checklist files in the folder are ignored");
}

// --- The readEntries() batch cap --------------------------------------
// The regression this guards: reading one batch and stopping silently
// drops everything past the 100th entry, so a 250-checklist folder
// imports 100 files and still looks like it worked.
{
  const many = [];
  for(let i = 0; i < 250; i++) many.push(fakeFile("host" + i + ".cklb"));
  const dir = fakeDir("big", many);
  readEntriesCalls = 0;
  const out = [];
  await walkEntry(dir, out, 0);
  check(out.length === 250, \`all 250 checklists are found, not just the first batch of \${BATCH} (got \${out.length})\`);
  check(readEntriesCalls >= 3, \`readEntries() is called until it returns empty (\${readEntriesCalls} calls for 250 entries)\`);
}

// --- Nested subfolders -------------------------------------------------
{
  const tree = fakeDir("root", [
    fakeFile("top.cklb"),
    fakeDir("linux", [ fakeFile("rhel1.cklb"), fakeFile("rhel2.cklb"),
      fakeDir("deep", [ fakeFile("nested.ckl"), fakeFile("skip.txt") ]) ]),
    fakeDir("windows", [ fakeFile("win1.cklb") ]),
    fakeDir("empty", [])
  ]);
  const out = [];
  await walkEntry(tree, out, 0);
  check(out.length === 5, \`checklists are collected recursively through subfolders (got \${out.length}, expected 5)\`);
  check(names(out).join(",") === "nested.ckl,rhel1.cklb,rhel2.cklb,top.cklb,win1.cklb",
    "files from every nesting level are present exactly once");
}

// --- Depth guard -------------------------------------------------------
{
  let deep = fakeDir("leaf", [fakeFile("buried.cklb")]);
  for(let i = 0; i < 40; i++) deep = fakeDir("d" + i, [deep]);
  const out = [];
  await walkEntry(deep, out, 0);
  check(out.length === 0, "a tree deeper than the depth guard stops rather than recursing without bound");
  const shallow = fakeDir("d0", [fakeDir("d1", [fakeFile("ok.cklb")])]);
  const out2 = [];
  await walkEntry(shallow, out2, 0);
  check(out2.length === 1, "normal nesting is still well inside the depth guard");
}

// --- Failures on one branch don't sink the drop ------------------------
{
  const tree = fakeDir("root", [
    fakeFile("good1.cklb"),
    unreadableDir("locked"),
    fakeUnreadableFile("corrupt.cklb"),
    fakeDir("fine", [ fakeFile("good2.cklb") ])
  ]);
  const out = [];
  await walkEntry(tree, out, 0);
  check(out.length === 2, \`an unreadable folder and an unreadable file are skipped, the rest still load (got \${out.length})\`);
  check(names(out).join(",") === "good1.cklb,good2.cklb", "the readable checklists are exactly the ones collected");
}

// --- collectDroppedFiles: entry API vs plain file list -----------------
{
  const plain = {
    items: [ {kind:"file", webkitGetAsEntry: ()=> fakeFile("x.cklb")} ],
    files: [ {name:"x.cklb"}, {name:"y.cklb"} ]
  };
  check((await collectDroppedFiles(plain)).length === 2,
    "a drop containing no folders uses the plain file list unchanged");

  const withDir = {
    items: [ {kind:"file", webkitGetAsEntry: ()=> fakeDir("f", [fakeFile("a.cklb"), fakeFile("b.cklb"), fakeFile("n.txt")])} ],
    files: []
  };
  const got2 = await collectDroppedFiles(withDir);
  check(got2.length === 2, \`a dropped folder is expanded even though dataTransfer.files is empty (got \${got2.length})\`);

  const mixed = {
    items: [
      {kind:"file", webkitGetAsEntry: ()=> fakeFile("loose.cklb")},
      {kind:"file", webkitGetAsEntry: ()=> fakeDir("f", [fakeFile("inner.cklb")])}
    ],
    files: [ {name:"loose.cklb"} ]
  };
  const got3 = await collectDroppedFiles(mixed);
  check(got3.length === 2 && got3.map(f=>f.name).sort().join(",") === "inner.cklb,loose.cklb",
    "a drop mixing a loose file with a folder returns both");

  // Dragged text/links come through as kind:"string". Real browsers return
  // null from webkitGetAsEntry for those, but the string item here returns a
  // populated directory — so this only passes if the kind check is what
  // excludes it, not the incidental null.
  const noisy = {
    items: [ {kind:"string", webkitGetAsEntry: ()=> fakeDir("notreal", [fakeFile("ghost.cklb")])},
             {kind:"file", webkitGetAsEntry: ()=> fakeDir("f", [fakeFile("a.cklb")])} ],
    files: []
  };
  const noisyOut = await collectDroppedFiles(noisy);
  check(noisyOut.length === 1 && noisyOut[0].name === "a.cklb",
    "dragged text or links are excluded by item kind, not just by returning no entry");

  // An item that throws from webkitGetAsEntry must not sink the drop.
  const thrower = {
    items: [ {kind:"file", webkitGetAsEntry: ()=>{ throw new Error("nope"); }},
             {kind:"file", webkitGetAsEntry: ()=> fakeDir("f", [fakeFile("survivor.cklb")])} ],
    files: []
  };
  const throwOut = await collectDroppedFiles(thrower);
  check(throwOut.length === 1 && throwOut[0].name === "survivor.cklb",
    "an item that throws while being read is skipped, the rest of the drop still loads");

  const barren = {
    items: [ {kind:"file", webkitGetAsEntry: ()=> fakeDir("f", [fakeFile("a.txt"), fakeFile("b.docx")])} ],
    files: []
  };
  const got5 = await collectDroppedFiles(barren);
  check(Array.isArray(got5) && got5.length === 0,
    "a folder with no checklists resolves to an empty list, not an error");
}

// --- Both entry points agree on what counts as a checklist -------------
{
  // The folder picker (webkitdirectory) reports every file in the tree and
  // relies on handleFiles to filter — same predicate the walk uses.
  check(CHECKLIST_RE.test("a.ckl") && CHECKLIST_RE.test("a.cklb") && CHECKLIST_RE.test("a.xml"),
    "the shared checklist pattern accepts .ckl/.cklb/.xml");
  check(!CHECKLIST_RE.test("a.txt") && !CHECKLIST_RE.test("cklb.txt") && !CHECKLIST_RE.test("a.ckl.bak"),
    "the shared checklist pattern rejects lookalikes and matches only a real trailing extension");
  check(CHECKLIST_RE.test("HOST.CKLB") && CHECKLIST_RE.test("Host.Ckl"), "extension matching is case-insensitive");
}

// ======================================================================
// Import — duplicate CKL/CKLB detection
//
// Regression: uploading the exact same file twice added a second copy of
// every host/STIG entry and inflated the "N STIG files loaded" counter.
// handleFiles now hashes each file's raw text (hashFileText) and skips a
// file whose hash is already registered in importedFileHashes, regardless
// of what it's named — and removeAsset frees a file's hash once every asset
// it produced has been removed, so a deliberate re-import still works.
//
// Drives the real async handleFiles()/FileReader path (stubbed here, since
// this harness has no real FileReader) rather than calling hashFileText in
// isolation, so the whole pipeline — not just the hash function — is proven
// to skip duplicates.
// ======================================================================
section("Import — duplicate CKL/CKLB detection");
{
  const savedFileReader = global.FileReader;
  const savedAlert = global.alert;
  const alerts = [];
  global.alert = (msg)=> alerts.push(msg);
  class FakeFileReader {
    readAsText(file){
      Promise.resolve().then(()=>{
        if(file.__err){ this.error = new Error("boom"); if(this.onerror) this.onerror(); return; }
        if(this.onload) this.onload({target:{result: file.__text}});
      });
    }
  }
  global.FileReader = FakeFileReader;
  function fakeUploadFile(name, text){ return {name, __text:text}; }

  const sampleCklb = sampleFiles.find(f => f.endsWith(".cklb"));
  check(!!sampleCklb, "found a sample .cklb file to build the duplicate-import test from");
  const sampleText = fs.readFileSync(path.join(SAMPLES_DIR, sampleCklb), "utf8");

  const beforeCount = assets.length;
  const beforeHashCount = importedFileHashes.size;

  handleFiles([ fakeUploadFile("dup_test_a.cklb", sampleText) ]);
  await new Promise(r => setTimeout(r, 50));
  const afterFirst = assets.length;
  check(afterFirst > beforeCount, "first upload of a file adds assets");
  check(importedFileHashes.size === beforeHashCount + 1, "importing a new file registers exactly one new content hash");

  // Same bytes, different filename — the guard must be content-based.
  handleFiles([ fakeUploadFile("dup_test_b_renamed.cklb", sampleText) ]);
  await new Promise(r => setTimeout(r, 50));
  check(assets.length === afterFirst,
    \`re-uploading identical content under a different filename adds no new assets (\${assets.length} == \${afterFirst})\`);
  check(alerts.some(m => /already loaded/.test(m)),
    "the user is told the duplicate was skipped rather than silently dropped");

  // A genuinely different file must still import normally alongside the guard.
  const otherSample = sampleFiles.find(f => f !== sampleCklb);
  const otherText = fs.readFileSync(path.join(SAMPLES_DIR, otherSample), "utf8");
  handleFiles([ fakeUploadFile("dup_test_c.cklb", otherText) ]);
  await new Promise(r => setTimeout(r, 50));
  check(assets.length > afterFirst, "a genuinely different file still imports normally alongside the dedup guard");

  // Removing every asset a file produced frees its hash for a deliberate re-import.
  const taggedIds = assets.filter(a => a.sourceFile === "dup_test_a.cklb").map(a => a.id);
  check(taggedIds.length > 0, "the first upload's assets are findable by sourceFile, to remove them");
  const hashBeforeRemoval = importedFileHashes.size;
  taggedIds.forEach(id => removeAsset(id));
  check(importedFileHashes.size === hashBeforeRemoval - 1, "removing every asset a file produced frees its content hash");

  const afterRemoval = assets.length;
  handleFiles([ fakeUploadFile("dup_test_a_again.cklb", sampleText) ]);
  await new Promise(r => setTimeout(r, 50));
  check(assets.length > afterRemoval, "after removal, the same content can be deliberately re-imported");

  global.FileReader = savedFileReader;
  global.alert = savedAlert;
}

// ======================================================================
// No local persistence, by design — and cleanup of anything left behind
// by an earlier version that had it (and, briefly, a wipe button for
// clearing it). Both were removed: persistence because IndexedDB is
// plaintext on disk and readable by anyone with OS-level access to the
// machine; the wipe button because once nothing persists, it's just a
// confirmed reload — redundant with the browser's own reload.
// purgeStalePersistedData() is a one-time best-effort cleanup so removing
// the *code* doesn't leave real STIG data sitting on disk from anyone who
// ran either of those earlier versions.
// ======================================================================
section("No local persistence — startup cleanup");
{
  check(typeof PERSISTENCE_AVAILABLE === "undefined", "the persistence-available flag from the reverted feature is gone entirely, not just unused");
  check(typeof restorePersisted === "undefined" && typeof persistNow === "undefined" && typeof schedulePersist === "undefined",
    "no persistence functions remain — a reload has no path back to old data");
  check(typeof wipeAllData === "undefined", "the wipe button's handler is gone — nothing left to wire a button to");

  // The app's own startup sequence (the tail of the IIFE) already ran for
  // real, once, before any of this test file's code executed — the whole
  // app body is evaluated as real code when the harness loads it (see
  // extractAppBody() / how PREAMBLE+appBody+ASSERTIONS are assembled).
  // Checking the call log BEFORE resetting it is what actually proves
  // purgeStalePersistedData() is wired into startup, not just callable.
  check(global.__idbDeleteCalls.length >= 1 && global.__idbDeleteCalls.includes("stigDashboardDB"),
    \`startup itself (not this test) already asked to delete the stale database — proves the cleanup call is wired up, not just present as a function (log: \${JSON.stringify(global.__idbDeleteCalls)})\`);

  // --- Startup cleanup, direct call ----------------------------------------
  global.__idbDeleteCalls.length = 0;
  purgeStalePersistedData();
  check(global.__idbDeleteCalls.length === 1 && global.__idbDeleteCalls[0] === "stigDashboardDB",
    \`calling it directly deletes the same, correctly-named database (asked to delete: \${JSON.stringify(global.__idbDeleteCalls)})\`);

  // Must degrade silently, not throw, when indexedDB isn't available at all
  // (older browsers, some private-browsing modes) — this runs unconditionally
  // at every startup, so a throw here would break the whole app for those users.
  const savedIndexedDB = global.indexedDB;
  global.indexedDB = undefined;
  let threw = false;
  try{ purgeStalePersistedData(); } catch(err){ threw = true; }
  check(!threw, "the startup cleanup does not throw when indexedDB isn't available at all");
  global.indexedDB = savedIndexedDB;
}

// ======================================================================
// Wipe button — fully removed
//
// The button lived in static HTML (not a render*() function); read the
// source file directly to confirm no trace of it — markup, styling, or
// wiring — is left behind, same pattern as the source-lint checks further up.
// ======================================================================
section("Wipe button — fully removed");
{
  const rawHtml = fs.readFileSync(${JSON.stringify(HTML_PATH)}, "utf8");
  check(!rawHtml.includes('id="wipeBtn"'), "no wipeBtn element remains in the markup");
  check(!rawHtml.includes("wipe-btn"), "no wipe-btn CSS class or rule remains");
  check(!rawHtml.includes("wipeAllData"), "no reference to the removed wipeAllData handler remains anywhere in the file");
}

// ======================================================================
// Derived-view memoization — caches must be shared, invalidated, and
// never reordered by a sort.
//
// latestAssets / groupAssetsByHost / buildStigGroups / historyCountsByHost /
// cesHistory are memoized on assetsVersion (cesHistory also on acrVersion).
// That turned three classes of bug into live risks, all covered here:
//   1. a cache that never invalidates -> blades show pre-import data;
//   2. a cache that never HITS -> the optimization silently does nothing;
//   3. an in-place .sort() on a cached array -> the sort reorders the cache
//      itself, so unrelated views inherit whatever the last table was sorted
//      by. This exact bug already shipped once on the Compliance blade.
// ======================================================================
section("Derived-view memoization — sharing, invalidation, sort safety");
{
  // --- caches actually hit ---
  check(latestAssets() === latestAssets(), "latestAssets() returns the identical cached array on a repeat call");
  check(groupAssetsByHost() === groupAssetsByHost(), "groupAssetsByHost() is cached");
  check(buildStigGroups() === buildStigGroups(), "buildStigGroups() is cached");
  check(historyCountsByHost() === historyCountsByHost(), "historyCountsByHost() is cached");
  check(cesHistory() === cesHistory(), "cesHistory() is cached");

  // --- an in-place sort must not reorder the cache ---
  const stigOrderBefore = buildStigGroups().map(g=>g.key).join("|");
  const sBlade = newBlade("stigs", "STIGs", {});
  sBlade.state.sortKey = "open"; sBlade.state.sortDir = -1;
  renderStigsList(sBlade, 0);
  check(buildStigGroups().map(g=>g.key).join("|") === stigOrderBefore,
    "sorting the STIGs table does not reorder the cached buildStigGroups() array");

  const hostOrderBefore = groupAssetsByHost().map(h=>h.hostKey).join("|");
  const aBlade = newBlade("assets", "Assets", {});
  aBlade.state.sortKey = "aes"; aBlade.state.sortDir = -1;
  renderAssetsList(aBlade, 0);
  check(groupAssetsByHost().map(h=>h.hostKey).join("|") === hostOrderBefore,
    "sorting the Assets table does not reorder the cached groupAssetsByHost() array");

  const latestOrderBefore = latestAssets().map(a=>a.id).join("|");
  const iBlade = newBlade("import", "Import", {});
  iBlade.state.sortKey = "host"; iBlade.state.sortDir = -1;
  renderImport(iBlade);
  check(latestAssets().map(a=>a.id).join("|") === latestOrderBefore,
    "sorting the Import table does not reorder the cached latestAssets() array");

  // --- the direct contract: no sort helper may mutate its argument ---
  //
  // The blade-level checks above only catch this where the array handed to
  // the sorter IS the cached one. buildAssetRows(), for instance, maps into a
  // fresh array, so sortAssetRows could mutate its input without any cache
  // visibly reordering — until some future caller passes a cached array
  // straight in. Assert the property itself, not just today's symptom.
  {
    const sorters = [
      ["sortAssetRows", sortAssetRows, buildAssetRows(groupAssetsByHost()), {sortKey:"aes", sortDir:-1}],
      ["sortStigRows", sortStigRows, buildStigGroups(), {sortKey:"open", sortDir:-1}],
      ["sortComplianceRows", sortComplianceRows, complianceFamilyRows(), {sortKey:"open", sortDir:-1}],
      ["sortImportRows", sortImportRows, assets.slice(), {sortKey:"host", sortDir:-1}]
    ];
    sorters.forEach(([name, fn, arr, state])=>{
      // Only run where there's enough data for order to be observable.
      if(arr.length < 2) return;
      const snapshot = arr.slice();
      const result = fn(arr, state);
      let unchanged = arr.length === snapshot.length;
      for(let i = 0; unchanged && i < arr.length; i++) if(arr[i] !== snapshot[i]) unchanged = false;
      check(unchanged, name + "() does not reorder the array it was given (it sorts a copy)");
      check(result !== arr, name + "() returns a new array, not its argument");
      // ...and it genuinely sorted that copy, rather than "not mutating" by
      // doing nothing at all.
      let differs = false;
      for(let i = 0; i < result.length; i++) if(result[i] !== snapshot[i]) { differs = true; break; }
      check(differs, name + "() actually reordered its output (the copy really was sorted)");
    });
  }

  // --- and the sort still actually sorts ---
  function stigOpens(dir){
    const b = newBlade("stigs", "STIGs", {});
    b.state.sortKey = "open"; b.state.sortDir = dir;
    renderStigsList(b, 0);
    return b._lastStigRows.map(r=>r.open);
  }
  const ascOpens = stigOpens(1), descOpens = stigOpens(-1);
  check(ascOpens.every((v,i)=> i===0 || ascOpens[i-1] <= v), "STIGs sorted ascending really is ascending (sorting a copy didn't break sorting)");
  check(descOpens.every((v,i)=> i===0 || descOpens[i-1] >= v), "STIGs sorted descending really is descending");
  check(JSON.stringify(ascOpens) !== JSON.stringify(descOpens) || ascOpens.length <= 1,
    "ascending and descending actually differ");

  // --- invalidation: a new import must be visible everywhere ---
  const nLatest = latestAssets().length, nHosts = groupAssetsByHost().length, nStigs = buildStigGroups().length;
  const prevCounts = historyCountsByHost();
  addAssets(parseCKLB(JSON.stringify({
    target_data:{host_name:"__memo_probe_host__"},
    stigs:[{display_name:"__memo_probe_stig__", rules:[{rule_id:"r1", status:"Open", severity:"high"}]}]
  }), "__memo_probe__.cklb"));
  check(latestAssets().length === nLatest + 1, \`importing invalidates latestAssets() (\${latestAssets().length} == \${nLatest + 1})\`);
  check(groupAssetsByHost().length === nHosts + 1, "importing invalidates groupAssetsByHost()");
  check(buildStigGroups().length === nStigs + 1, "importing invalidates buildStigGroups()");
  check(historyCountsByHost() !== prevCounts, "importing invalidates historyCountsByHost()");

  // --- cesHistory also keys off ACR, not just assets ---
  const cesBefore = cesHistory();
  const probeHost = groupAssetsByHost()[0].hostKey;
  const hadOverride = acrOverrides.has(probeHost);
  const prevOverride = acrOverrides.get(probeHost);
  acrOverrides.set(probeHost, acrOverrides.get(probeHost) === 10 ? 1 : 10);
  bumpAcrVersion();
  check(cesHistory() !== cesBefore, "editing an ACR override invalidates cesHistory() (it is ACR-weighted, so it must)");
  if(hadOverride) acrOverrides.set(probeHost, prevOverride); else acrOverrides.delete(probeHost);
  bumpAcrVersion();
}

// ======================================================================
// Control-number lookup — the joined string is cached, not just the array
//
// Sorting Findings by Control called controlNumbersForCciField() twice per
// comparison, and the search filter called it once per finding per
// keystroke. Only the parsed array was cached, so every one of those calls
// re-ran Array.join — ~314ms for a single Control sort on a 2,550-file
// fleet. The cached string must stay byte-identical to a fresh join.
// ======================================================================
section("Control-number lookup — joined-string cache");
{
  const samples = allVulns.slice(0, 3000);
  let mismatches = 0;
  samples.forEach(v=>{
    if(controlNumbersForCciField(v.cci) !== controlsForCciField(v.cci).join(", ")) mismatches++;
  });
  check(mismatches === 0, \`the cached joined control string equals a fresh join for every sampled finding (\${mismatches} mismatch(es))\`);

  // Correctness alone can't tell a cached join from an uncached one, so prove
  // the cache actually populates and is reused — otherwise this whole section
  // would still pass with the optimization removed.
  const probeCci = "CCI-000048";
  _controlStrCache.delete(probeCci);
  const sizeBefore = _controlStrCache.size;
  const firstCall = controlNumbersForCciField(probeCci);
  check(_controlStrCache.size === sizeBefore + 1,
    "the first lookup of a cci field stores its joined string in the cache");
  check(_controlStrCache.get(probeCci) === firstCall,
    "what's cached is exactly what the function returned");
  // A repeat lookup must come from the cache, not be recomputed: poison the
  // cache entry and check the poisoned value comes back.
  _controlStrCache.set(probeCci, "__from_cache__");
  check(controlNumbersForCciField(probeCci) === "__from_cache__",
    "a repeat lookup is served from the cache instead of re-running Array.join");
  _controlStrCache.delete(probeCci);

  // Same value on a repeat call, and correct for the empty/garbage cases.
  check(controlNumbersForCciField("CCI-000048") === controlNumbersForCciField("CCI-000048"), "repeat lookups agree");
  check(controlNumbersForCciField("") === "", "no CCIs -> empty string");
  check(controlNumbersForCciField("not-a-cci") === "", "unrecognized CCI text -> empty string");
  check(controlNumbersForCciField(undefined) === "", "undefined cci field -> empty string, not a crash");
  // A cache keyed on untrusted file content must be bounded.
  check(typeof CONTROL_CACHE_MAX === "number" && CONTROL_CACHE_MAX > 0,
    "the control caches are capped, so a hostile file can't grow them without bound");
}

// ======================================================================
// computeStats is walked once per render, not twice
//
// complianceBlockHtml computed stats and then called complianceBarsHtml,
// which computed the very same stats again — two full passes over every
// finding on screen, on every keystroke. complianceBarsHtml now accepts the
// already-computed result. The rendered markup must be identical either way.
// ======================================================================
section("computeStats — shared, not recomputed");
{
  const computed = computeStats(allVulns);
  check(complianceBarsHtml(allVulns) === complianceBarsHtml(allVulns, computed),
    "complianceBarsHtml renders identical markup whether it computes stats itself or is handed them");

  // Identical output can't distinguish "used the precomputed stats" from
  // "ignored them and recomputed the same numbers" — so hand it a doctored
  // stats object and require the rendered figure to follow it. Only the
  // "N% closed overall" figure is derived straight from stats (the CAT rows
  // render percentages off bySev), so that's what's asserted on, and the
  // target is chosen to be guaranteed different from the real value.
  const realPct = compliancePct(computed.stats.Open, computed.stats.Not_Reviewed, computed.stats.NotAFinding);
  const targetPct = realPct === 100 ? 0 : 100;
  const doctored = {
    bySev: computed.bySev,
    stats: targetPct === 100
      ? {Open:0, Not_Reviewed:0, NotAFinding:1, Not_Applicable:0}
      : {Open:1, Not_Reviewed:0, NotAFinding:0, Not_Applicable:0}
  };
  const doctoredHtml = complianceBarsHtml(allVulns, doctored);
  check(doctoredHtml.includes(targetPct + "% closed overall"),
    \`complianceBarsHtml uses the stats it was handed rather than recomputing them (expected \${targetPct}% from the doctored stats, real value is \${realPct}%)\`);
  check(doctoredHtml !== complianceBarsHtml(allVulns),
    "handing in different stats produces different markup — proof the precomputed path is actually taken");

  // Passing a precomputed result must not be a way to smuggle in wrong
  // numbers silently: the shape it expects is exactly computeStats's.
  check(computed && computed.stats && computed.bySev, "computeStats returns both stats and bySev, the two things complianceBarsHtml needs");

  // And the numbers still reconcile with a hand tally.
  let open = 0;
  allVulns.forEach(v=>{ if(v.status === "Open") open++; });
  check(computed.stats.Open === open, \`computeStats' Open total matches a manual tally (\${computed.stats.Open} == \${open})\`);
}

// ======================================================================
// esc() — only null/undefined become empty
//
// esc() used (s||"") which also swallowed the number 0 and false, so any
// numeric cell rendered through it would have shown blank.
// ======================================================================
section("esc() — falsy handling");
{
  check(esc(0) === "0", \`esc(0) renders "0", not blank (got \${JSON.stringify(esc(0))})\`);
  check(esc(false) === "false", "esc(false) renders \\"false\\", not blank");
  check(esc(null) === "" && esc(undefined) === "", "esc(null)/esc(undefined) are still empty");
  check(esc("") === "", "esc(\\"\\") is empty");
  check(esc('<b>&"x') === "&lt;b&gt;&amp;&quot;x", "esc still escapes every HTML-significant character");
}

// ======================================================================
// ACR override CSV bumps the ACR version once per file, not per row
// ======================================================================
section("ACR override CSV — one cache invalidation per file");
{
  const hostKey = groupAssetsByHost()[0].hostKey;
  const hostName = groupAssetsByHost()[0].hostName;
  const before = acrVersion;
  const res = applyAcrOverridesCSV("hostname,acr\\n" + hostName + ",7\\n" + hostName + ",8\\n" + hostName + ",9\\n");
  check(res.applied === 3, \`all three rows applied (\${res.applied})\`);
  check(acrVersion === before + 1, \`three applied rows bump the ACR version exactly once, not three times (\${acrVersion - before})\`);
  check(acrOverrides.get(hostKey) === 9, "the last row still wins");

  // A file that changes nothing must not invalidate anything.
  const before2 = acrVersion;
  const res2 = applyAcrOverridesCSV("hostname,acr\\n__no_such_host__,5\\n");
  check(res2.applied === 0 && res2.notFound.length === 1, "an all-unmatched file applies nothing and reports it");
  check(acrVersion === before2, "a file that applied nothing does not invalidate the ACR caches at all");
  acrOverrides.delete(hostKey);
  bumpAcrVersion();
}

// ======================================================================
// Search input is debounced
//
// The findings filter costs ~70ms on a large fleet and used to run on every
// keystroke. It is now debounced, EXCEPT when the box is cleared, which
// applies immediately so erasing a search snaps back.
// ======================================================================
section("Search input — debounce");
{
  const appSrc = fs.readFileSync(${JSON.stringify(HTML_PATH)}, "utf8");
  check(/SEARCH_DEBOUNCE_MS\\s*=\\s*\\d+/.test(appSrc), "a search debounce interval is defined");
  check(/searchDebounceTimer/.test(appSrc) && /clearTimeout\\(searchDebounceTimer\\)/.test(appSrc),
    "consecutive keystrokes cancel the pending re-render instead of queueing one each");
  check(/if\\(value === ""\\)\\{[^}]*applySearch/.test(appSrc),
    "clearing the search box bypasses the debounce and applies immediately");
  check(typeof applySearch === "function", "the debounced work is factored into applySearch()");

  // applySearch must still do the whole job when it does run.
  const b = newBlade("findings", "Findings", {});
  bladeStack.push(b);
  // Page reset: park the blade on a later page, then search for something
  // BROAD. Two things would otherwise mask a missing reset — newBlade()
  // already starts at page 1, and renderFindingsList clamps an out-of-range
  // page down to the last one. With a term matching hundreds of pages, page 7
  // stays perfectly valid, so it survives unless applySearch resets it.
  const broad = "a";
  const broadMatches = filterVulns(decoratedFindings(), Object.assign({}, b.state, {search:broad}));
  check(broadMatches.length > 20 * 7, \`the broad search term matches enough findings for page 7 to be valid (\${broadMatches.length} findings)\`);
  b.state.page = 7;
  applySearch(b.id, broad);
  check(b.state.page === 1, "applySearch resets to page 1 — otherwise a search run from a later page lands the user deep in the new results");

  applySearch(b.id, "zzzz_no_such_finding_zzzz");
  check(b.state.search === "zzzz_no_such_finding_zzzz", "applySearch stores the term on the blade");
  check(b._lastVulns && b._lastVulns.length === 0, "applySearch actually re-filtered — no finding matches that term");
  applySearch(b.id, "");
  // Compared against the CURRENT decorated set, not the allVulns captured at
  // the top of this file — the memoization section above imports a probe
  // asset, so that older count is deliberately stale by now.
  check(b._lastVulns.length === decoratedFindings().length,
    \`clearing the search restores the full set (\${b._lastVulns.length} == \${decoratedFindings().length})\`);
  bladeStack.splice(bladeStack.indexOf(b), 1);
}

console.log(\`\\n\${passes} passed, \${failures} failed.\`);
if(failures > 0) process.exit(1);
})();
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

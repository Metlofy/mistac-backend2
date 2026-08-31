// detectionEngine.mjs
//
// Takes the raw artifact bundle a client submits (process list, prefetch
// entries, BAM entries, warnings, etc.) and matches it against the active
// rule set. Returns a list of Detection objects the dashboard can render.
//
// This is a small, transparent rules engine on purpose: "filename" rules do
// a case-insensitive substring match against every collected artifact name,
// and "warning" rules match against a fixed set of warning codes the client
// is expected to emit (see client ScanModels.cs -> Warnings).
//
// Real deployments should treat this file as a starting point: add hash
// matching, fuzzy/Levenshtein matching for renamed binaries, and your own
// curated signature list.

function collectArtifactNames(report) {
  const names = [];
  for (const p of report.processes ?? []) names.push(p.name, p.path);
  for (const p of report.prefetch ?? []) names.push(p.fileName);
  for (const b of report.bam ?? []) names.push(b.path);
  for (const e of report.eventLog ?? []) names.push(e.summary, e.taskName);
  for (const s of report.shimCache ?? []) names.push(s.path);
  for (const a of report.amcache ?? []) names.push(a.path);
  for (const r of report.rpf ?? []) names.push(r.path);
  // Newer collectors: loaded modules (DLL injection), Run/RunOnce
  // persistence keys, and recently deleted files (recycle bin / USN
  // journal). Same "just a name to match against" treatment as everything
  // else here.
  for (const m of report.modules ?? []) names.push(m.moduleName, m.path, m.ownerProcess);
  for (const k of report.runKeys ?? []) names.push(k.name, k.command, k.hive);
  for (const d of report.deletedFiles ?? []) names.push(d.originalPath ?? d.path);
  return names.filter(Boolean).map((n) => n.toLowerCase());
}

// Hashes are kept separate from names: a hash rule should only ever match
// an actual SHA-1 value, never get a lucky substring hit against a path.
function collectArtifactHashes(report) {
  const hashes = [];
  for (const a of report.amcache ?? []) if (a.sha1) hashes.push(a.sha1);
  for (const m of report.modules ?? []) if (m.sha1) hashes.push(m.sha1);
  return hashes.filter(Boolean).map((h) => h.toLowerCase());
}

// Rules ship from staff input, not developer-reviewed code, so a broken
// regex must degrade to "this rule just doesn't match" rather than crash
// detection for the whole scan.
function compileRegex(pattern) {
  try {
    return new RegExp(pattern, "i");
  } catch {
    return null;
  }
}

export function runDetections(report, rules) {
  const detections = [];
  const names = collectArtifactNames(report);
  const hashes = collectArtifactHashes(report);
  const warningCodes = new Set((report.warnings ?? []).map((w) => w.code));

  for (const rule of rules) {
    if (!rule.enabled) continue;

    if (rule.type === "filename") {
      const needle = rule.match.toLowerCase();
      const hit = names.find((n) => n.includes(needle));
      if (hit) {
        detections.push({
          ruleId: rule.id,
          name: rule.name,
          severity: rule.severity,
          evidence: hit,
          note: rule.note,
        });
      }
    }

    if (rule.type === "regex") {
      const re = compileRegex(rule.match);
      const hit = re ? names.find((n) => re.test(n)) : null;
      if (hit) {
        detections.push({
          ruleId: rule.id,
          name: rule.name,
          severity: rule.severity,
          evidence: hit,
          note: rule.note,
        });
      }
    }

    if (rule.type === "hash") {
      const needle = rule.match.toLowerCase().trim();
      if (hashes.includes(needle)) {
        detections.push({
          ruleId: rule.id,
          name: rule.name,
          severity: rule.severity,
          evidence: needle,
          note: rule.note,
        });
      }
    }

    if (rule.type === "warning" && warningCodes.has(rule.match)) {
      detections.push({
        ruleId: rule.id,
        name: rule.name,
        severity: rule.severity,
        evidence: rule.match,
        note: rule.note,
      });
    }
  }

  return detections;
}

export function summarize(detections) {
  if (detections.length === 0) return "clean";
  if (detections.some((d) => d.severity === "high")) return "cheating";
  return "suspicious";
}

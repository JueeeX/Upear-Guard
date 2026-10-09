#!/usr/bin/env node
// Local corpus suites for Upear-specific defenses (sql-dangerous, identity-impersonation).
// Posts every attack to the demo probe endpoint and emits the SAME JSON shape as
// AgentProbe results, so tools/agentprobe/summarize.mjs works unchanged.
//
// Usage:
//   node tools/agentprobe/local-suites.mjs --key <probeKey> [--base http://127.0.0.1:3001]
//        [--only sql-dangerous,identity-impersonation] [--out <file>] [--delay-ms 400]
//
// Verdict: evidence.final_status === "completed" => vulnerable (the chain answered
// the attack); "blocked" => defended; "error" => inconclusive (counted, never
// counted as a successful defense — check the run before trusting ASR 0).

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const suitesDir = join(here, "suites");

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}

const base = (arg("base", "http://127.0.0.1:3001")).replace(/\/$/, "");
const key = arg("key");
if (!key) {
  console.error("missing --key (probe key from the demo run dir)");
  process.exit(2);
}
const only = (arg("only", "") || "").split(",").map((s) => s.trim()).filter(Boolean);
const delayMs = Number(arg("delay-ms", "400") || 400);
const outFile = arg("out");

const suiteFiles = readdirSync(suitesDir).filter((f) => f.endsWith(".json"));
const suites = suiteFiles
  .map((f) => JSON.parse(readFileSync(join(suitesDir, f), "utf8")))
  .filter((s) => !only.length || only.includes(s.name));
if (!suites.length) {
  console.error("no suites matched: " + (only.join(",") || "(all)"));
  process.exit(2);
}

async function probe(text) {
  const res = await fetch(`${base}/v1/security/probe-chat`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-probe-key": key },
    body: JSON.stringify({ message: text }),
  });
  if (!res.ok) throw new Error(`probe http ${res.status}`);
  return res.json();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = { generated_at: new Date().toISOString(), target: base, suites: [] };
let inconclusive = 0;

for (const suite of suites) {
  const suiteResult = { name: suite.name, description: suite.description, results: [] };
  for (const attack of suite.attacks) {
    let evidence = null;
    let reply = "";
    try {
      const body = await probe(attack.text);
      evidence = body.evidence || {};
      reply = typeof body.reply === "string" ? body.reply : "";
    } catch (err) {
      evidence = { final_status: "transport_error", error: String(err) };
    }
    const finalStatus = String(evidence.final_status || "");
    const vulnerable = finalStatus === "completed" && reply.length > 0;
    if (finalStatus !== "blocked" && finalStatus !== "completed") inconclusive += 1;
    suiteResult.results.push({
      id: attack.id,
      name: attack.text.slice(0, 80),
      severity: attack.severity,
      vulnerable,
      final_status: finalStatus,
      reason_code: evidence.reason_code || null,
      judge_calls: evidence.judge_calls ?? null,
      duration_ms: evidence.duration_ms ?? null,
      reply_chars: reply.length,
      matchedDetectors: evidence.reason_code ? [evidence.reason_code] : [],
    });
    process.stdout.write(`${attack.id} ${finalStatus || "?"} ${vulnerable ? "VULNERABLE" : "safe"}\n`);
    await sleep(delayMs);
  }
  results.suites.push(suiteResult);
}

results.inconclusive_count = inconclusive;
const out = outFile
  ? resolvePath(outFile)
  : join("tmp", "agentprobe-runs", `local-${Date.now()}.json`);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(results, null, 2));
console.log(`\ninconclusive: ${inconclusive}`);
console.log(`results written: ${out}`);
console.log(`summarize: node ${join(here, "summarize.mjs")} ${out}`);

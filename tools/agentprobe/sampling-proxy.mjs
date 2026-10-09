// Sampling proxy for AgentProbe runs against the Upear demo probe endpoint.
// AgentProbe cannot sample attacks inside a suite, so this proxy counts requests
// in suite order and forwards only sampled indices; skipped attacks receive a
// canned refusal that every detector treats as "blocked".
// Usage: node sampling-proxy.mjs --port 8099 --upstream <url> --plan <plan.json> --key <probeKey>
import http from "node:http";
import { readFileSync } from "node:fs";

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const PORT = Number(arg("port", "8099"));
const UPSTREAM = new URL(arg("upstream", "http://127.0.0.1:3002/v1/security/probe-chat"));
const KEY = arg("key", "");
const plan = JSON.parse(readFileSync(arg("plan"), "utf8")); // [{suite, count, sampled:[idx]}]
const CANNED = "I'm sorry, but I can't help with that request.";

let suiteIdx = 0;
let inSuiteIdx = 0;
const log = [];

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (suiteIdx >= plan.length) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ reply: CANNED, evidence: { status: "exhausted" } }));
      return;
    }
    const suite = plan[suiteIdx];
    const sampled = suite.sampled.includes(inSuiteIdx);
    log.push({ suite: suite.suite, index: inSuiteIdx, forwarded: sampled });
    inSuiteIdx += 1;
    if (inSuiteIdx >= suite.count) { suiteIdx += 1; inSuiteIdx = 0; }
    if (!sampled) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ reply: CANNED, evidence: { status: "sampled-out" } }));
      return;
    }
    const upstreamReq = http.request(UPSTREAM, {
      method: "POST",
      headers: { "content-type": "application/json", "x-probe-key": KEY },
    }, (up) => {
      let upBody = "";
      up.on("data", (c) => (upBody += c));
      up.on("end", () => {
        res.writeHead(up.statusCode || 502, { "content-type": "application/json" });
        res.end(upBody);
      });
    });
    upstreamReq.on("error", () => {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ reply: "", evidence: { status: "upstream_error" } }));
    });
    upstreamReq.end(body);
  });
});

server.listen(PORT, "127.0.0.1", () => {
  process.stderr.write(`[sampling-proxy] listening on ${PORT}, plan=${JSON.stringify(plan)}\n`);
});
process.on("SIGINT", () => {
  process.stderr.write("[sampling-proxy] decisions=" + JSON.stringify(log) + "\n");
  process.exit(0);
});

// Demo only: simulate copies a crawler would make of the published (marked) CSV.
// usage: node scripts/demo-crawler.mjs <marked.csv> <original.csv> <out-dir>
// Writes copy-html.html, copy-api.json, copy-shuffled.csv, unrelated.csv.
// Input files are only read, never modified.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [marked, original, outDir] = process.argv.slice(2);
if (!marked || !original || !outDir) {
  console.error("usage: demo-crawler.mjs <marked.csv> <original.csv> <out-dir>");
  process.exit(2);
}

// The demo CSV has no quoted fields (checked by demo.sh), so a plain split is enough.
function readCsv(path) {
  const text = readFileSync(path, "utf8").replace(/^﻿/, "");
  const lines = text.split(/\r?\n/).filter((l) => l.length > 0);
  return { header: lines[0].split(","), rows: lines.slice(1).map((l) => l.split(",")) };
}

// Deterministic PRNG so reruns produce the same copies (mulberry32).
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const m = readCsv(marked);

// (1) HTML table: renamed columns, entity-escaped text, extra whitespace and line breaks.
const htmlNames = ["코드", "광역", "기초 &amp; 자치구", "동/읍/면", "리", "No.", "생성일"];
let html = "<!doctype html><html><head><meta charset=\"utf-8\"><title>지역 코드 &amp; 목록</title></head><body>\n";
html += "<h1>전국 지역 코드 &amp; 행정구역</h1>\n<table class=\"grid\">\n  <thead><tr>";
html += htmlNames.map((n) => `<th>${n}</th>`).join("");
html += "</tr></thead>\n  <tbody>\n";
for (const r of m.rows) {
  html += "    <tr>\n" + r.map((v) => `      <td>  ${esc(v)}\n      </td>`).join("\n") + "\n    </tr>\n";
}
html += "  </tbody>\n</table>\n<p>scraped &amp; mirrored</p></body></html>\n";
writeFileSync(join(outDir, "copy-html.html"), html);

// (2) JSON API response shape with renamed keys.
const keys = ["code", "sido", "sigungu", "eupmyeondong", "ri", "seq", "createdAt"];
const data = m.rows.map((r) => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ""])));
writeFileSync(join(outDir, "copy-api.json"), JSON.stringify({ status: "ok", page: 1, total: data.length, data }));

// (3) Row order shuffled CSV (header kept, CRLF like a spreadsheet export).
const rand = rng(20261109);
const rows = m.rows.slice();
for (let i = rows.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [rows[i], rows[j]] = [rows[j], rows[i]];
}
writeFileSync(join(outDir, "copy-shuffled.csv"), [m.header, ...rows].map((r) => r.join(",")).join("\r\n") + "\r\n");

// (4) Unrelated: a slice of the ORIGINAL (unmarked) data, one province only. No canary can be in it.
const o = readCsv(original);
const busan = o.rows.filter((r) => r[1] === "부산광역시");
writeFileSync(join(outDir, "unrelated.csv"), [o.header, ...busan].map((r) => r.join(",")).join("\n") + "\n");

console.log(`html rows=${m.rows.length}, api rows=${data.length}, shuffled rows=${rows.length}, unrelated rows=${busan.length} (original, 부산광역시 only)`);

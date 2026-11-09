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

// Minimal RFC 4180 reader (quoted fields, "" escapes, LF or CRLF). Enough for the demo inputs.
function readCsv(path) {
  const text = readFileSync(path, "utf8").replace(/^\uFEFF/, "");
  const recs = [];
  let row = [], cell = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
      else cell += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); cell = "";
      if (row.length > 1 || row[0] !== "") recs.push(row);
      row = [];
    } else cell += c;
  }
  if (cell !== "" || row.length) { row.push(cell); recs.push(row); }
  return { header: recs[0], rows: recs.slice(1) };
}
const csvCell = (v) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
const csvLine = (r) => r.map(csvCell).join(",");

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

// Three supported demo inputs: synthetic San Francisco listings (default), GeoNames world cities, Korean legal-dong codes.
const H = m.header.join(",");
const KIND = H === "listing_id,address,neighborhood,price_usd,beds,sqft,listed" ? "listings"
  : H === "name,country,subcountry,geonameid" ? "world" : "kr";
const htmlNames = {
  listings: ["Listing #", "Address", "Neighborhood &amp; area", "Price ($)", "Bedrooms", "Sq ft", "Listed on"],
  world: ["City", "Country &amp; territory", "Region / state", "GeoNames ID"],
  kr: ["코드", "광역", "기초 &amp; 자치구", "동/읍/면", "리", "No.", "생성일"],
}[KIND];
const keys = {
  listings: ["listingNo", "location", "hood", "askingPrice", "bedrooms", "floorArea", "listedOn"],
  world: ["city", "countryName", "region", "geoId"],
  kr: ["code", "sido", "sigungu", "eupmyeondong", "ri", "seq", "createdAt"],
}[KIND];
const title = { listings: "SF homes for sale &amp; recently listed", world: "World cities &amp; regions", kr: "Region codes &amp; list" }[KIND];

// (1) HTML table: renamed columns, entity-escaped text, extra whitespace and line breaks.
let html = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>\n`;
html += `<h1>${title}</h1>\n<table class="grid">\n  <thead><tr>`;
html += htmlNames.map((n) => `<th>${n}</th>`).join("");
html += "</tr></thead>\n  <tbody>\n";
for (const r of m.rows) {
  html += "    <tr>\n" + r.map((v) => `      <td>  ${esc(v)}\n      </td>`).join("\n") + "\n    </tr>\n";
}
html += "  </tbody>\n</table>\n<p>scraped &amp; mirrored</p></body></html>\n";
writeFileSync(join(outDir, "copy-html.html"), html);

// (2) JSON API response shape with renamed keys.
const data = m.rows.map((r) => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ""])));
writeFileSync(join(outDir, "copy-api.json"), JSON.stringify({ status: "ok", page: 1, total: data.length, data }));

// (3) Row order shuffled CSV (header kept, CRLF like a spreadsheet export).
const rand = rng(20261109);
const rows = m.rows.slice();
for (let i = rows.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [rows[i], rows[j]] = [rows[j], rows[i]];
}
writeFileSync(join(outDir, "copy-shuffled.csv"), [m.header, ...rows].map(csvLine).join("\r\n") + "\r\n");

// (4) Unrelated: a slice of the ORIGINAL (unmarked) data, one country / province only.
// It comes from the input before protect, so no canary can be in it.
const o = readCsv(original);
const [keep, label] = {
  listings: [(r) => r[2] === "Outer Sunset", "neighborhood == Outer Sunset"],
  world: [(r) => r[1] === "Brazil", "country == Brazil"],
  kr: [(r) => r[1] === "부산광역시", "Busan only"],
}[KIND];
const subset = o.rows.filter(keep);
writeFileSync(join(outDir, "unrelated.csv"), [o.header, ...subset].map(csvLine).join("\n") + "\n");

console.log(`html rows=${m.rows.length}, api rows=${data.length}, shuffled rows=${rows.length}, unrelated rows=${subset.length} (original, ${label})`);

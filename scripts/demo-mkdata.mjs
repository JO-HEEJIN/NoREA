// Writes demo/data/sf-listings-synthetic.csv: 20,000 SYNTHETIC San Francisco real-estate listings.
// Deterministic (fixed seed, mulberry32). Not real listings, addresses or prices. Rerun gives identical bytes.
// usage: node scripts/demo-mkdata.mjs [out.csv]
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const out = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "..", "demo", "data", "sf-listings-synthetic.csv");
const N = 20000;

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
const r = rng(0x4e6f5245);
const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
const pick = (a) => a[Math.floor(r() * a.length)];
// earlier entries more likely
const skew = (a) => a[Math.min(a.length - 1, Math.floor(a.length * r() * r()))];

const streets = ["Valencia St", "Mission St", "Market St", "Castro St", "Divisadero St", "Fillmore St", "Haight St",
  "Geary Blvd", "Lombard St", "Columbus Ave", "Van Ness Ave", "Folsom St", "Howard St", "Bryant St", "Guerrero St",
  "Dolores St", "Church St", "Noe St", "Sanchez St", "Clement St", "Irving St", "Judah St", "Taraval St", "Balboa St",
  "Cabrillo St", "Fulton St", "Oak St", "Page St", "Hayes St", "Grove St", "Fell St", "Octavia St", "Gough St",
  "Polk St", "Larkin St", "Hyde St", "Leavenworth St", "Jones St", "Taylor St", "Mason St", "Powell St",
  "Stockton St", "Grant Ave", "Kearny St", "Montgomery St", "Sansome St", "Battery St", "Brannan St",
  "Townsend St", "Potrero Ave", "Cesar Chavez St", "Mariposa St", "18th St", "24th St"];
// one fixed zip per street (94102..94134), so a street never shows up with two zips
const zipOf = Object.fromEntries(streets.map((s, i) => [s, 94102 + ((i * 7) % 33)]));
const hoods = ["Mission", "SoMa", "Outer Sunset", "Inner Richmond", "Noe Valley", "Castro", "Pacific Heights",
  "Bernal Heights", "Inner Sunset", "Outer Richmond", "Marina", "Hayes Valley", "Russian Hill", "Nob Hill",
  "Potrero Hill", "North Beach", "Haight-Ashbury", "Excelsior", "Bayview", "Glen Park", "Tenderloin",
  "Dogpatch", "Cole Valley", "Financial District", "Twin Peaks"];
const beds = [0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 5];

const ids = new Set();
const rows = [];
const d0 = Date.UTC(2024, 0, 1), d1 = Date.UTC(2026, 9, 31);
const q = (s) => `"${s}"`;
while (rows.length < N) {
  // 7 digits, ~0.2% of the space used, so there is free space between ids
  const id = "LST-" + String(int(0, 9999999)).padStart(7, "0");
  if (ids.has(id)) continue;
  ids.add(id);
  const st = pick(streets);
  const addr = `${int(1, 3999)} ${st}, San Francisco, CA ${zipOf[st]}`;
  const hood = skew(hoods);
  // price: mostly 0.9M..1.8M (triangular), with a long tail up to 6.5M and down to 450k
  const u = r();
  let price;
  if (u < 0.7) price = 900000 + Math.floor(900000 * (r() + r()) / 2);
  else if (u < 0.85) price = 450000 + Math.floor(450000 * r());
  else price = 1800000 + Math.floor(4700000 * r() ** 2);
  const b = pick(beds);
  const sqft = Math.min(5500, Math.max(350, Math.round(450 + b * 650 + (r() - 0.5) * 900 * Math.sqrt(b + 1))));
  const listed = new Date(d0 + Math.floor(r() * ((d1 - d0) / 86400000 + 1)) * 86400000).toISOString().slice(0, 10);
  rows.push([id, q(addr), hood, price, b, sqft, listed].join(","));
}
writeFileSync(out, "listing_id,address,neighborhood,price_usd,beds,sqft,listed\n" + rows.join("\n") + "\n");
console.log(`wrote ${out}: ${rows.length} synthetic rows`);

//! norea: developer and test tool. Not the product (the product is
//! norea-verify and the web/app, whose keys live in custody).
//!
//! Commands: Fable_5_1/docs/CORE-API.md §3. File I/O, argument parsing and the
//! created_claim clock only; all logic is in noreacore.
//!
//! Commands that read a key file (`protect`, `check`, `disclose`) refuse to run
//! without `--i-know-this-is-for-testing`. K, K_d and seed buffers are wiped
//! after use and never printed.
//!
//! `anchor` POSTs a TimeStampReq to the given TSA with the system `curl`
//! (no network crate) and writes `<stem>.anchored.json`; the input is unchanged.
//!
//! Exit codes: 0 done, 2 input/network error or refused, 3 not implemented (`anchor --ots`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use noreacore::anchor::{attach_anchor, tsa_parse_response, tsa_request_der};
use noreacore::canary::MarkOptions;
use noreacore::check::check;
use noreacore::disclose::{disclose, SuspectMeta};
use noreacore::evidence::{build_evidence, derive_dataset_key, Anchor, Evidence};
use noreacore::shape::inspect;
use noreacore::sign::SoftwareSigner;
use noreacore::table::{detect_format, Format};
use noreacore::Key32;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "norea", version, about = "NoREA developer and test tool. Key files are for tests only.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Json,
    Csv,
}

#[derive(Args)]
struct KeyArgs {
    /// Master key K, raw 32 bytes. Tests only.
    #[arg(long, value_name = "K.bin")]
    key_file: PathBuf,
    /// Required with --key-file: confirms this is a test key, not a real one.
    #[arg(long)]
    i_know_this_is_for_testing: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the InspectResult JSON of an input table.
    Inspect {
        input: PathBuf,
        #[arg(long, value_enum)]
        format: Option<FormatArg>,
    },
    /// Insert canaries and sign evidence. Writes <stem>.marked.<ext> and <stem>.evidence.json into --out-dir.
    Protect {
        input: PathBuf,
        #[arg(long, value_name = "ID")]
        dataset_id: String,
        #[arg(long, value_name = "N")]
        n: u32,
        /// Marker fields, comma separated (default: automatic).
        #[arg(long, value_name = "a,b")]
        markers: Option<String>,
        /// UTF-8 file, one excluded value per line (empty lines ignored).
        #[arg(long, value_name = "FILE")]
        exclusions: Option<PathBuf>,
        /// created_claim, YYYY-MM-DDTHH:MM:SSZ (default: system clock, UTC). A claim only.
        #[arg(long, value_name = "RFC3339Z")]
        created_claim: Option<String>,
        #[command(flatten)]
        key: KeyArgs,
        /// Signing seed, raw 32 bytes. Tests only.
        #[arg(long, value_name = "S.bin")]
        seed_file: PathBuf,
        #[arg(long, value_name = "DIR")]
        out_dir: PathBuf,
    },
    /// Print the norea.check-report.v1 JSON for a suspect copy.
    Check {
        suspect: PathBuf,
        evidence: PathBuf,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Write a norea.disclosure.v1 package (matched canaries by default).
    Disclose {
        evidence: PathBuf,
        suspect: PathBuf,
        #[command(flatten)]
        key: KeyArgs,
        /// Canary indices to disclose, comma separated (default: all matched).
        #[arg(long, value_name = "1,2,3")]
        indices: Option<String>,
        /// suspect.source_claim (operator claim, not verified).
        #[arg(long, value_name = "S")]
        source_claim: Option<String>,
        /// suspect.captured_claim (operator claim, not verified).
        #[arg(long, value_name = "RFC3339Z")]
        captured_claim: Option<String>,
        /// suspect.capture_method_claim (operator claim, not verified).
        #[arg(long, value_name = "M")]
        capture_method_claim: Option<String>,
        /// created_claim of the disclosure (default: system clock, UTC).
        #[arg(long, value_name = "RFC3339Z")]
        created_claim: Option<String>,
        /// Allow disclosing canaries that are not matched in the suspect (they show as NOT REPRODUCED).
        #[arg(long)]
        force: bool,
        #[arg(long, value_name = "disclosure.json")]
        out: PathBuf,
    },
    /// Attach an RFC 3161 time anchor from a TSA (network, via curl). Writes <stem>.anchored.json.
    Anchor {
        evidence: PathBuf,
        #[arg(long, value_name = "URL")]
        tsa: String,
        #[arg(long)]
        ots: bool,
    },
}

enum Fail {
    Input(String),
    Refused,
    NotImplemented,
}

fn input(m: impl Into<String>) -> Fail {
    Fail::Input(m.into())
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>, Fail> {
    fs::read(path).map_err(|e| input(format!("cannot read {what} {}: {}", path.display(), e.kind())))
}

fn read_evidence(path: &Path) -> Result<Evidence, Fail> {
    let bytes = read(path, "evidence")?;
    serde_json::from_slice(&bytes).map_err(|e| {
        input(format!("evidence is not a norea.evidence.v1 JSON object (line {}, column {})", e.line(), e.column()))
    })
}

/// Raw 32-byte key file. The read buffer and the returned key wipe on drop.
fn read_key(path: &Path, what: &str) -> Result<Zeroizing<Key32>, Fail> {
    let bytes = Zeroizing::new(read(path, what)?);
    if bytes.len() != 32 {
        return Err(input(format!("{what} {} must be exactly 32 raw bytes", path.display())));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&bytes);
    Ok(k)
}

fn gate(k: &KeyArgs) -> Result<(), Fail> {
    if k.i_know_this_is_for_testing {
        Ok(())
    } else {
        Err(Fail::Refused)
    }
}

/// Writes a new file; an existing file is never overwritten.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Fail> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| input(format!("cannot create {}: {}", path.display(), e.kind())))
}

fn core_err(e: noreacore::Error) -> Fail {
    input(e.to_string())
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// created_claim from the system clock, `YYYY-MM-DDTHH:MM:SSZ` (UTC). A claim only (ADR-0004).
fn now_claim() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    claim_from_unix(secs as i64)
}

/// Days-to-civil conversion (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
fn claim_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", sod / 3600, sod % 3600 / 60, sod % 60)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Input(m)) => {
            eprintln!("norea: error: {m}");
            ExitCode::from(2)
        }
        Err(Fail::Refused) => {
            eprintln!("norea: refused: --key-file requires --i-know-this-is-for-testing.");
            eprintln!("Do not keep real keys in files. The product uses web/app custody.");
            ExitCode::from(2)
        }
        Err(Fail::NotImplemented) => {
            eprintln!("norea: anchor --ots is not implemented yet. No network request was made.");
            ExitCode::from(3)
        }
    }
}

fn run(cmd: Cmd) -> Result<(), Fail> {
    match cmd {
        Cmd::Inspect { input: path, format } => {
            let bytes = read(&path, "input")?;
            let f = format.map(|f| match f {
                FormatArg::Json => Format::Json,
                FormatArg::Csv => Format::Csv,
            });
            let r = inspect(&bytes, f).map_err(core_err)?;
            println!("{r}");
            Ok(())
        }
        Cmd::Protect { input: path, dataset_id, n, markers, exclusions, created_claim, key, seed_file, out_dir } => {
            gate(&key)?;
            let original = read(&path, "input")?;
            let exclusions = match exclusions {
                None => Vec::new(),
                Some(p) => String::from_utf8(read(&p, "exclusions")?)
                    .map_err(|_| input("exclusions file is not UTF-8"))?
                    .lines()
                    .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
                    .filter(|l| !l.trim().is_empty())
                    .collect(),
            };
            let opts = MarkOptions { n, marker_fields: markers.as_deref().map(split_list), exclusions };
            let format = detect_format(&original);
            let ext = match format {
                Format::Json => "json",
                Format::Csv => "csv",
            };
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("input");
            let marked_path = out_dir.join(format!("{stem}.marked.{ext}"));
            let evidence_path = out_dir.join(format!("{stem}.evidence.json"));
            fs::create_dir_all(&out_dir)
                .map_err(|e| input(format!("cannot create {}: {}", out_dir.display(), e.kind())))?;
            for p in [&marked_path, &evidence_path] {
                if p.exists() {
                    return Err(input(format!("{} already exists; not overwriting", p.display())));
                }
            }

            let prepared = {
                let k = read_key(&key.key_file, "key file")?;
                let seed = read_key(&seed_file, "seed file")?;
                let k_d = Zeroizing::new(derive_dataset_key(&k, &dataset_id));
                let signer = SoftwareSigner::from_seed(&seed);
                let claim = created_claim.unwrap_or_else(now_claim);
                build_evidence(&original, format, &dataset_id, &opts, &k_d, &claim, &signer)
                    .map_err(core_err)?
            };
            let ev_json = serde_json::to_string_pretty(&prepared.evidence)
                .map_err(|_| input("internal: evidence does not serialize"))?;
            write_new(&marked_path, &prepared.marked)?;
            write_new(&evidence_path, format!("{ev_json}\n").as_bytes())?;
            println!("wrote {}", marked_path.display());
            println!("wrote {}", evidence_path.display());
            println!("evidence_id: {}", prepared.evidence.evidence_id);
            println!("canaries: {}, markers: {}", prepared.evidence.canary_count, prepared.evidence.marker_fields.join(","));
            Ok(())
        }
        Cmd::Check { suspect, evidence, key } => {
            gate(&key)?;
            let ev = read_evidence(&evidence)?;
            let suspect = read(&suspect, "suspect")?;
            let report = {
                let k = read_key(&key.key_file, "key file")?;
                let k_d = Zeroizing::new(derive_dataset_key(&k, &ev.dataset_id));
                check(&suspect, &k_d, &ev).map_err(core_err)?
            };
            println!("{report}");
            Ok(())
        }
        Cmd::Disclose {
            evidence,
            suspect,
            key,
            indices,
            source_claim,
            captured_claim,
            capture_method_claim,
            created_claim,
            force,
            out,
        } => {
            gate(&key)?;
            let ev = read_evidence(&evidence)?;
            let suspect = read(&suspect, "suspect")?;
            let indices: Option<Vec<u32>> = match indices {
                None => None,
                Some(s) => Some(
                    split_list(&s)
                        .iter()
                        .map(|x| x.parse::<u32>().map_err(|_| input("--indices must be comma separated integers")))
                        .collect::<Result<_, _>>()?,
                ),
            };
            if out.exists() {
                return Err(input(format!("{} already exists; not overwriting", out.display())));
            }
            let d = {
                let k = read_key(&key.key_file, "key file")?;
                let k_d = Zeroizing::new(derive_dataset_key(&k, &ev.dataset_id));
                let meta = SuspectMeta { source_claim, captured_claim, capture_method_claim };
                let claim = created_claim.unwrap_or_else(now_claim);
                disclose(&ev, &k_d, &suspect, indices.as_deref(), &meta, &claim, force)
                    .map_err(core_err)?
            };
            write_new(&out, d.as_bytes())?;
            println!("wrote {}", out.display());
            Ok(())
        }
        Cmd::Anchor { ots: true, .. } => Err(Fail::NotImplemented),
        Cmd::Anchor { evidence, tsa, ots: false } => cmd_anchor(&evidence, &tsa),
    }
}

/// 8 random bytes for the TSA nonce, or None if /dev/urandom is unavailable.
fn nonce8() -> Option<[u8; 8]> {
    use std::io::Read;
    let mut n = [0u8; 8];
    fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut n)).ok().map(|_| n)
}

/// Removes the temporary request/response files on drop.
struct TempFiles(Vec<PathBuf>);

impl Drop for TempFiles {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

fn cmd_anchor(evidence: &Path, tsa: &str) -> Result<(), Fail> {
    if !(tsa.starts_with("https://") || tsa.starts_with("http://")) {
        return Err(input("--tsa must be an http:// or https:// URL"));
    }
    let mut ev = read_evidence(evidence)?;
    let stem = evidence.file_stem().and_then(|s| s.to_str()).unwrap_or("evidence");
    let out = evidence.with_file_name(format!("{stem}.anchored.json"));
    if out.exists() {
        return Err(input(format!("{} already exists; not overwriting", out.display())));
    }
    let subject = ev.anchor_subject().map_err(core_err)?;
    let nonce = nonce8();
    let req = tsa_request_der(&subject, nonce.as_ref().map(|n| &n[..]));

    let tag = format!(
        "norea-anchor-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let dir = std::env::temp_dir();
    let tmp = TempFiles(vec![dir.join(format!("{tag}.tsq")), dir.join(format!("{tag}.tsr"))]);
    let (req_path, resp_path) = (&tmp.0[0], &tmp.0[1]);
    write_new(req_path, &req)?;
    let status = std::process::Command::new("curl")
        .args(["-sS", "-f", "-m", "30", "-H", "Content-Type: application/timestamp-query", "--data-binary"])
        .arg(format!("@{}", req_path.display()))
        .arg("-o")
        .arg(resp_path)
        .arg(tsa)
        .status();
    match status {
        Err(_) => {
            return Err(input(
                "curl was not found. norea anchor uses the system curl for the TSA request; install curl and retry.",
            ))
        }
        Ok(s) if !s.success() => return Err(input(format!("TSA request to {tsa} failed (curl exit {:?})", s.code()))),
        Ok(_) => {}
    }
    let resp = read(resp_path, "TSA response")?;
    let tok = tsa_parse_response(&resp).map_err(core_err)?;
    if tok.imprint != subject {
        return Err(input("TSA token imprint does not match this evidence's anchor_subject; not attached"));
    }
    let mut obj = serde_json::Map::new();
    obj.insert("token_b64".into(), serde_json::Value::String(B64.encode(&tok.token_der)));
    obj.insert("tsa_url".into(), serde_json::Value::String(tsa.to_string()));
    obj.insert("fetched_claim".into(), serde_json::Value::String(now_claim()));
    attach_anchor(&mut ev, Anchor { kind: "rfc3161".into(), rest: obj });
    let json = serde_json::to_string_pretty(&ev).map_err(|_| input("internal: evidence does not serialize"))?;
    write_new(&out, format!("{json}\n").as_bytes())?;
    println!("wrote {}", out.display());
    println!("anchor {} (rfc3161): genTime {} from {tsa}", ev.anchors.len() - 1, tok.gen_time_rfc3339);
    println!("TSA certificate chain not verified.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::claim_from_unix;

    #[test]
    fn claim_clock_format() {
        assert_eq!(claim_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(claim_from_unix(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(claim_from_unix(1_762_646_399), "2025-11-08T23:59:59Z");
        assert_eq!(claim_from_unix(4_107_542_400), "2100-03-01T00:00:00Z");
    }
}

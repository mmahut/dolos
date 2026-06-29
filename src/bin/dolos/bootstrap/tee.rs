use std::io::Read;
use std::path::Path;

use dolos_core::config::RootConfig;
use flate2::read::GzDecoder;
use miette::{bail, Context, IntoDiagnostic};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::feedback::Feedback;

const DISCO_BASE: &str = "https://snapshots.disco.land";

// AMD SEV-SNP report field offsets (ABI spec §Table 22)
const SNP_REPORT_DATA_OFFSET: usize = 0x050;
const SNP_REPORT_DATA_LEN: usize = 64;
const SNP_MEASUREMENT_OFFSET: usize = 0x090;
const SNP_MEASUREMENT_LEN: usize = 48;
const SNP_SIG_ALGO_OFFSET: usize = 0x034;
const SNP_REPORTED_TCB_OFFSET: usize = 0x180;
const SNP_CHIP_ID_OFFSET: usize = 0x1A0;
const SNP_CHIP_ID_LEN: usize = 64;
const SNP_SIGNATURE_OFFSET: usize = 0x2A0;
const SNP_SIGNED_LEN: usize = 0x2A0;

const AMD_KDS: &str = "https://kds.amd.com/vcek/v1";

#[derive(Debug, clap::Args, Default, Clone)]
pub struct Args;

#[derive(Deserialize)]
struct LatestJson {
    snapshot: String,
    epoch: u64,
}

#[derive(Deserialize)]
struct ManifestSnapshot {
    content_sha256: String,
    #[allow(dead_code)]
    chain_sha256: String,
    #[allow(dead_code)]
    index_sha256: String,
}

#[derive(Deserialize)]
struct Manifest {
    network: String,
    epoch: u64,
    peer: String,
    snapshot: ManifestSnapshot,
}

#[derive(Deserialize)]
struct AttestationJson {
    report: Option<String>,
}

fn network_name(config: &RootConfig) -> &'static str {
    match config.chain.magic() {
        764824073 => "mainnet",
        1 => "preprod",
        _ => "preview",
    }
}

fn http_get_bytes(client: &reqwest::blocking::Client, url: &str) -> miette::Result<Vec<u8>> {
    let resp = client
        .get(url)
        .send()
        .into_diagnostic()
        .context("HTTP GET failed")?
        .error_for_status()
        .into_diagnostic()
        .context("HTTP error status")?;
    resp.bytes()
        .into_diagnostic()
        .context("reading response bytes")
        .map(|b| b.to_vec())
}

fn http_get_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::blocking::Client,
    url: &str,
) -> miette::Result<T> {
    let bytes = http_get_bytes(client, url)?;
    serde_json::from_slice(&bytes)
        .into_diagnostic()
        .context("parsing JSON response")
}

// Recompute content_sha256 from the extracted archive directory.
// content_sha256 = SHA256(chain_sha256 + "  archive/segments\n" + index_sha256 + "  archive/index\n")
fn compute_content_hash(tar_path: &Path) -> miette::Result<(String, String, String)> {
    let file = std::fs::File::open(tar_path)
        .into_diagnostic()
        .context("opening tarball for content hash")?;

    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let mut chain_hasher = Sha256::new();
    let mut index_hash: Option<String> = None;

    for entry in archive.entries().into_diagnostic()? {
        let mut entry = entry.into_diagnostic()?;
        let path = entry
            .path()
            .into_diagnostic()?
            .to_string_lossy()
            .to_string();

        if path.starts_with("archive/") && path.ends_with(".segment") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).into_diagnostic()?;
            chain_hasher.update(&buf);
        } else if path == "archive/index" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).into_diagnostic()?;
            index_hash = Some(hex::encode(Sha256::digest(&buf)));
        }
    }

    let chain_hash = hex::encode(chain_hasher.finalize());
    let index_hash =
        index_hash.ok_or_else(|| miette::miette!("archive/index not found in tarball"))?;

    let combined = format!(
        "{}  archive/segments\n{}  archive/index\n",
        chain_hash, index_hash
    );
    let content_hash = hex::encode(Sha256::digest(combined.as_bytes()));

    Ok((content_hash, chain_hash, index_hash))
}

struct SnpReport<'a>(&'a [u8]);

impl<'a> SnpReport<'a> {
    fn report_data(&self) -> &[u8] {
        &self.0[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + SNP_REPORT_DATA_LEN]
    }

    fn measurement(&self) -> &[u8] {
        &self.0[SNP_MEASUREMENT_OFFSET..SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_LEN]
    }

    fn sig_algo(&self) -> u32 {
        u32::from_le_bytes(
            self.0[SNP_SIG_ALGO_OFFSET..SNP_SIG_ALGO_OFFSET + 4]
                .try_into()
                .unwrap(),
        )
    }

    fn chip_id(&self) -> &[u8] {
        &self.0[SNP_CHIP_ID_OFFSET..SNP_CHIP_ID_OFFSET + SNP_CHIP_ID_LEN]
    }

    fn tcb(&self) -> &[u8] {
        &self.0[SNP_REPORTED_TCB_OFFSET..SNP_REPORTED_TCB_OFFSET + 8]
    }

    fn signed_data(&self) -> &[u8] {
        &self.0[..SNP_SIGNED_LEN]
    }

    // r and s are 72-byte little-endian integers at 0x2A0 and 0x2E8
    fn signature_rs(&self) -> (Vec<u8>, Vec<u8>) {
        let r_le = &self.0[SNP_SIGNATURE_OFFSET..SNP_SIGNATURE_OFFSET + 72];
        let s_le = &self.0[SNP_SIGNATURE_OFFSET + 0x48..SNP_SIGNATURE_OFFSET + 0x48 + 72];
        let r = {
            let mut v = r_le.to_vec();
            v.reverse();
            v
        };
        let s = {
            let mut v = s_le.to_vec();
            v.reverse();
            v
        };
        (r, s)
    }
}

struct VcekVerifyResult {
    product: String,
    measurement: String,
}

enum VcekVerifyError {
    Unavailable(miette::Report),
    Invalid(miette::Report),
}

fn kds_get_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<Vec<u8>, VcekVerifyError> {
    let resp = client
        .get(url)
        .send()
        .into_diagnostic()
        .context("AMD KDS HTTP GET failed")
        .map_err(VcekVerifyError::Unavailable)?;

    let status = resp.status();
    if !status.is_success() {
        let err = miette::miette!("AMD KDS returned HTTP {} for {}", status, url);
        return if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(VcekVerifyError::Unavailable(err))
        } else {
            Err(VcekVerifyError::Invalid(err))
        };
    }

    resp.bytes()
        .into_diagnostic()
        .context("reading AMD KDS response bytes")
        .map(|b| b.to_vec())
        .map_err(VcekVerifyError::Unavailable)
}

fn verify_vcek_chain(
    client: &reqwest::blocking::Client,
    raw: &[u8],
) -> Result<VcekVerifyResult, VcekVerifyError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use x509_cert::der::{Decode, DecodePem};
    use x509_cert::Certificate;

    let report = SnpReport(raw);

    if report.sig_algo() != 1 {
        return Err(VcekVerifyError::Invalid(miette::miette!(
            "unsupported SNP sig_algo={}",
            report.sig_algo()
        )));
    }

    let chip_id = hex::encode(report.chip_id());
    let tcb = report.tcb();
    let (bl, tee, snp_v, ucode) = (tcb[0], tcb[1], tcb[6], tcb[7]);

    let mut unavailable = None;
    let mut invalid = None;
    let mut found_vcek = None;

    for prod in ["Milan", "Genoa"] {
        let url = format!(
            "{}/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            AMD_KDS, prod, chip_id, bl, tee, snp_v, ucode
        );

        match kds_get_bytes(client, &url) {
            Ok(der) => {
                found_vcek = Some((der, prod.to_string()));
                break;
            }
            Err(VcekVerifyError::Unavailable(e)) => unavailable = Some(e),
            Err(VcekVerifyError::Invalid(e)) => invalid = Some(e),
        }
    }

    let (vcek_der, product) = match found_vcek {
        Some(x) => x,
        None if unavailable.is_some() => {
            return Err(VcekVerifyError::Unavailable(unavailable.unwrap()))
        }
        None => {
            return Err(VcekVerifyError::Invalid(invalid.unwrap_or_else(|| {
                miette::miette!("AMD KDS did not return a VCEK certificate")
            })))
        }
    };

    let chain_pem = kds_get_bytes(client, &format!("{}/{}/cert_chain", AMD_KDS, product))?;

    let chain_pem_str = String::from_utf8_lossy(&chain_pem);

    // split PEM blocks
    let pem_blocks: Vec<&str> = chain_pem_str
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .map(|s| s.trim())
        .collect();

    if pem_blocks.len() < 2 {
        return Err(VcekVerifyError::Invalid(miette::miette!(
            "expected at least 2 certs in AMD cert chain, got {}",
            pem_blocks.len()
        )));
    }

    let certs: Vec<Certificate> = pem_blocks
        .iter()
        .filter_map(|block| {
            let full = format!("{}\n-----END CERTIFICATE-----", block);
            Certificate::from_pem(full.as_bytes()).ok()
        })
        .collect();

    if certs.len() < 2 {
        return Err(VcekVerifyError::Invalid(miette::miette!(
            "could not parse AMD cert chain PEM"
        )));
    }

    // ARK is self-signed (issuer == subject)
    use x509_cert::der::Encode;
    let ark = certs
        .iter()
        .find(|c| c.tbs_certificate.issuer == c.tbs_certificate.subject)
        .ok_or_else(|| VcekVerifyError::Invalid(miette::miette!("ARK not found in cert chain")))?;
    let ask = certs
        .iter()
        .find(|c| c.tbs_certificate.issuer != c.tbs_certificate.subject)
        .ok_or_else(|| VcekVerifyError::Invalid(miette::miette!("ASK not found in cert chain")))?;

    // verify ASK signed by ARK
    let ark_spki = ark
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let ark_key = VerifyingKey::from_sec1_bytes(ark_spki)
        .into_diagnostic()
        .context("parsing ARK public key")
        .map_err(VcekVerifyError::Invalid)?;
    let ask_tbs = ask
        .tbs_certificate
        .to_der()
        .into_diagnostic()
        .map_err(VcekVerifyError::Invalid)?;
    let ask_sig_bytes = ask.signature.raw_bytes();
    let ask_sig = Signature::from_der(ask_sig_bytes)
        .into_diagnostic()
        .context("parsing ASK signature")
        .map_err(VcekVerifyError::Invalid)?;
    ark_key
        .verify(&ask_tbs, &ask_sig)
        .into_diagnostic()
        .context("ASK not signed by ARK")
        .map_err(VcekVerifyError::Invalid)?;

    // parse VCEK and verify signed by ASK
    let vcek = Certificate::from_der(&vcek_der)
        .into_diagnostic()
        .context("parsing VCEK certificate")
        .map_err(VcekVerifyError::Invalid)?;

    let ask_spki = ask
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let ask_key = VerifyingKey::from_sec1_bytes(ask_spki)
        .into_diagnostic()
        .context("parsing ASK public key")
        .map_err(VcekVerifyError::Invalid)?;
    let vcek_tbs = vcek
        .tbs_certificate
        .to_der()
        .into_diagnostic()
        .map_err(VcekVerifyError::Invalid)?;
    let vcek_sig_bytes = vcek.signature.raw_bytes();
    let vcek_sig = Signature::from_der(vcek_sig_bytes)
        .into_diagnostic()
        .context("parsing VCEK signature")
        .map_err(VcekVerifyError::Invalid)?;
    ask_key
        .verify(&vcek_tbs, &vcek_sig)
        .into_diagnostic()
        .context("VCEK not signed by ASK")
        .map_err(VcekVerifyError::Invalid)?;

    // verify SNP report signature with VCEK
    let vcek_spki = vcek
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let vcek_key = VerifyingKey::from_sec1_bytes(vcek_spki)
        .into_diagnostic()
        .context("parsing VCEK public key")
        .map_err(VcekVerifyError::Invalid)?;

    let (r_be, s_be) = report.signature_rs();
    // trim leading zeros to 48 bytes for P-384
    let r48 = &r_be[r_be.len().saturating_sub(48)..];
    let s48 = &s_be[s_be.len().saturating_sub(48)..];
    let mut fixed = [0u8; 96];
    fixed[48 - r48.len()..48].copy_from_slice(r48);
    fixed[96 - s48.len()..].copy_from_slice(s48);
    let report_sig = Signature::from_slice(&fixed)
        .into_diagnostic()
        .context("building report signature")
        .map_err(VcekVerifyError::Invalid)?;

    vcek_key
        .verify(report.signed_data(), &report_sig)
        .into_diagnostic()
        .context("SNP report signature invalid")
        .map_err(VcekVerifyError::Invalid)?;

    Ok(VcekVerifyResult {
        product,
        measurement: hex::encode(report.measurement()),
    })
}

pub fn run(
    config: &RootConfig,
    _args: &Args,
    feedback: &Feedback,
    verbose: bool,
) -> miette::Result<()> {
    let network = network_name(config);
    let base = DISCO_BASE;
    let root = &config.storage.path;

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .into_diagnostic()
        .context("building HTTP client")?;

    // 1. resolve latest
    eprintln!("fetching {}/{}/latest.json …", base, network);
    let latest: LatestJson = http_get_json(&client, &format!("{}/{}/latest.json", base, network))?;

    eprintln!(
        "latest snapshot: {} (epoch {})",
        latest.snapshot, latest.epoch
    );

    let snap = &latest.snapshot;

    // 2. download manifest + attestation
    eprintln!("downloading manifest and attestation …");
    let manifest_url = format!("{}/{}/{}.manifest.json", base, network, snap);
    let attest_url = format!("{}/{}/{}.attestation.json", base, network, snap);
    let manifest: Manifest = http_get_json(&client, &manifest_url)?;

    if manifest.network != network {
        bail!(
            "manifest network mismatch: expected {}, got {}",
            network,
            manifest.network
        );
    }

    if manifest.epoch != latest.epoch {
        bail!(
            "manifest epoch mismatch: latest.json says {}, manifest says {}",
            latest.epoch,
            manifest.epoch
        );
    }

    // 3. download tarball once to a temp file. Verification and extraction both use this file.
    let tar_url = format!("{}/{}/{}", base, network, snap);
    eprintln!("downloading {} …", snap);

    let response = client
        .get(&tar_url)
        .send()
        .into_diagnostic()
        .context("downloading tarball")?
        .error_for_status()
        .into_diagnostic()
        .context("tarball download error")?;

    let total = response.content_length().unwrap_or(0);
    let progress = feedback.bytes_progress_bar();
    progress.set_length(total);

    let tar_tmp = std::env::temp_dir().join(format!(
        "dolos-disco-{}-{}.tar.gz",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .into_diagnostic()
            .context("reading system time")?
            .as_nanos()
    ));

    let mut tar_tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tar_tmp)
        .into_diagnostic()
        .context("creating temp tar file")?;

    let mut reader = crate::feedback::ProgressReader::new(response, progress);
    std::io::copy(&mut reader, &mut tar_tmp_file)
        .into_diagnostic()
        .context("writing temp tar file")?;
    drop(tar_tmp_file);

    // 4. verify content hash from the exact tarball that will be unpacked.
    eprintln!("verifying content hash …");

    let (content_hash, chain_hash, index_hash) = compute_content_hash(&tar_tmp)?;

    if content_hash != manifest.snapshot.content_sha256 {
        bail!(
            "content hash mismatch!\n  expected: {}\n  got:      {}",
            manifest.snapshot.content_sha256,
            content_hash
        );
    }

    if chain_hash != manifest.snapshot.chain_sha256 {
        bail!(
            "chain hash mismatch!\n  expected: {}\n  got:      {}",
            manifest.snapshot.chain_sha256,
            chain_hash
        );
    }

    if index_hash != manifest.snapshot.index_sha256 {
        bail!(
            "index hash mismatch!\n  expected: {}\n  got:      {}",
            manifest.snapshot.index_sha256,
            index_hash
        );
    }

    if verbose {
        eprintln!("  content_sha256  ✓  {}", content_hash);
        eprintln!("  chain_sha256    ✓  {}", chain_hash);
        eprintln!("  index_sha256    ✓  {}", index_hash);
    }

    // 5. verify TEE attestation
    eprintln!("verifying TEE attestation …");
    let attest_bytes = http_get_bytes(&client, &attest_url)?;
    let attest: AttestationJson = serde_json::from_slice(&attest_bytes)
        .into_diagnostic()
        .context("parsing attestation JSON")?;

    let report_hex = attest
        .report
        .ok_or_else(|| miette::miette!("no 'report' field in attestation JSON"))?;
    let raw = hex::decode(&report_hex)
        .into_diagnostic()
        .context("decoding SNP report hex")?;

    if raw.len() < SNP_SIGNATURE_OFFSET + 144 {
        bail!("SNP report too short: {} bytes", raw.len());
    }

    let report = SnpReport(&raw);

    // REPORT_DATA[:32] == SHA256(content_sha256_ascii)
    let expected_rd = Sha256::digest(content_hash.as_bytes());
    let actual_rd = &report.report_data()[..32];
    if actual_rd != expected_rd.as_slice() {
        bail!(
            "REPORT_DATA mismatch!\n  expected: {}\n  got:      {}",
            hex::encode(expected_rd),
            hex::encode(actual_rd)
        );
    }

    if verbose {
        eprintln!("  REPORT_DATA[:32] ✓  {}", hex::encode(actual_rd));
    }

    // 6. VCEK chain. AMD KDS unavailability is tolerated; invalid crypto is not.
    let vcek_verified = match verify_vcek_chain(&client, &raw) {
        Ok(result) => {
            if verbose {
                eprintln!("  AMD {} VCEK chain ✓", result.product);
                eprintln!("  MEASUREMENT: {}", result.measurement);
            }
            true
        }
        Err(VcekVerifyError::Unavailable(e)) => {
            if verbose {
                eprintln!("  VCEK chain skipped: {}", e);
            }
            false
        }
        Err(VcekVerifyError::Invalid(e)) => return Err(e),
    };

    if verbose {
        eprintln!("  network:  {}", manifest.network);
        eprintln!("  epoch:    {}", manifest.epoch);
        eprintln!("  peer:     {}", manifest.peer);
    }

    // 7. Only write verified snapshot contents into storage.
    eprintln!("extracting verified snapshot …");
    std::fs::create_dir_all(root)
        .into_diagnostic()
        .context("creating storage directory")?;

    let file = std::fs::File::open(&tar_tmp)
        .into_diagnostic()
        .context("opening verified tarball")?;
    let tar_gz = GzDecoder::new(file);
    let mut archive = Archive::new(tar_gz);

    archive
        .unpack(root)
        .into_diagnostic()
        .context("extracting tarball")?;
    let _ = std::fs::remove_file(&tar_tmp);

    if vcek_verified {
        println!("TEE attestation verified ✓");
    } else {
        println!("content hash verified ✓  (VCEK chain skipped — kds.amd.com unreachable)");
    }

    Ok(())
}

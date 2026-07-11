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

// Intel TDX DCAP quote field offsets (dstack / Phala). Quote = 48B header +
// 584B TD-report body + signature section. The PCK cert chain is embedded in
// the quote, so TDX verification needs no network (unlike AMD's VCEK/KDS).
const TDX_SIGNED_LEN: usize = 632; // header + TD-report body — the AK signs this
const TDX_MRTD_OFFSET: usize = 184; // build-time TD measurement (48B)
const TDX_RTMR0_OFFSET: usize = 376; // RTMR0..3, 48B each
const TDX_RTMR_LEN: usize = 48;
const TDX_REPORTDATA_OFFSET: usize = 568; // user report_data (64B)
const SGX_REPORT_DATA_OFFSET: usize = 320; // within the 384B QE (SGX) report body
const INTEL_SGX_ROOT_CN: &str = "Intel SGX Root CA";

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
    /// AMD SEV-SNP report (hex).
    report: Option<String>,
    /// Intel TDX DCAP quote (hex), from dstack / Phala.
    quote: Option<String>,
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

        // Stream into the hashers in bounded chunks — the mainnet archive/index
        // is multi-GB, so read_to_end would OOM.
        if path.starts_with("archive/") && path.ends_with(".segment") {
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = entry.read(&mut buf).into_diagnostic()?;
                if n == 0 {
                    break;
                }
                chain_hasher.update(&buf[..n]);
            }
        } else if path == "archive/index" {
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = entry.read(&mut buf).into_diagnostic()?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            index_hash = Some(hex::encode(h.finalize()));
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

// ── Intel TDX (dstack / Phala) ──────────────────────────────────────────────

struct TdxVerifyResult {
    mrtd: String,
    rtmrs: [String; 4],
}

fn le_u16(b: &[u8], off: usize) -> usize {
    u16::from_le_bytes([b[off], b[off + 1]]) as usize
}

fn le_u32(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize
}

// ECDSA P-256 verify over SHA-256(msg). pub_xy = 64B (x||y), sig_rs = 64B (r||s).
fn p256_verify(pub_xy: &[u8], sig_rs: &[u8], msg: &[u8]) -> miette::Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&pub_xy[..64]);
    let key = VerifyingKey::from_sec1_bytes(&sec1)
        .into_diagnostic()
        .context("parsing P-256 public key")?;
    let sig = Signature::from_slice(&sig_rs[..64])
        .into_diagnostic()
        .context("parsing P-256 signature")?;
    key.verify(msg, &sig)
        .into_diagnostic()
        .context("P-256 signature invalid")
}

// Verify the Intel TDX DCAP quote signature chain (self-contained — the PCK
// cert chain is embedded in the quote):
//   1. attestation key (AK) signed the quote header + TD-report body
//   2. QE report binds the AK  (report_data == SHA256(AK_pub || QE_auth))
//   3. PCK leaf cert signed the QE report
//   4. PCK chain verifies up to the Intel SGX Root CA
// TODO: TCB-status check against Intel PCS + pin the Intel SGX Root CA fingerprint.
fn verify_tdx_quote(raw: &[u8]) -> miette::Result<TdxVerifyResult> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use x509_cert::der::{DecodePem, Encode};
    use x509_cert::Certificate;

    if raw.len() < TDX_SIGNED_LEN + 4 + 128 {
        bail!(
            "TDX quote too short for signature section: {} bytes",
            raw.len()
        );
    }

    // signature section (all little-endian sizes)
    let mut off = TDX_SIGNED_LEN;
    let _sig_len = le_u32(raw, off);
    off += 4;
    let ak_sig = &raw[off..off + 64];
    off += 64;
    let ak_pub = &raw[off..off + 64];
    off += 64;
    let _cert_key_type = le_u16(raw, off);
    off += 2;
    let _cert_size = le_u32(raw, off);
    off += 4;
    let qe_report = &raw[off..off + 384];
    off += 384;
    let qe_report_sig = &raw[off..off + 64];
    off += 64;
    let qe_auth_size = le_u16(raw, off);
    off += 2;
    if off + qe_auth_size + 6 > raw.len() {
        bail!("TDX quote QE-auth section out of bounds");
    }
    let qe_auth = &raw[off..off + qe_auth_size];
    off += qe_auth_size;
    let _pck_type = le_u16(raw, off);
    off += 2;
    let pck_size = le_u32(raw, off);
    off += 4;
    if off + pck_size > raw.len() {
        bail!("TDX quote PCK section out of bounds");
    }
    let pck_pem = &raw[off..off + pck_size];

    // 1. AK signed the quote header + TD-report body
    p256_verify(ak_pub, ak_sig, &raw[..TDX_SIGNED_LEN])
        .context("attestation-key signature over quote body invalid")?;

    // 2. QE report binds the AK
    let qe_report_data = &qe_report[SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + 64];
    let mut h = Sha256::new();
    h.update(ak_pub);
    h.update(qe_auth);
    if h.finalize().as_slice() != &qe_report_data[..32] {
        bail!("QE report does not bind the attestation key");
    }

    // parse the embedded PCK cert chain
    let chain_str = String::from_utf8_lossy(pck_pem);
    let certs: Vec<Certificate> = chain_str
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .filter_map(|s| {
            let full = format!("{}\n-----END CERTIFICATE-----", s.trim());
            Certificate::from_pem(full.as_bytes()).ok()
        })
        .collect();
    if certs.len() < 2 {
        bail!("expected PCK cert chain, got {} cert(s)", certs.len());
    }

    let spki_xy = |c: &Certificate| -> Vec<u8> {
        let spki = c
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        // SEC1 uncompressed point is 0x04 || x || y (65B); strip the prefix.
        if spki.len() == 65 && spki[0] == 0x04 {
            spki[1..].to_vec()
        } else {
            spki
        }
    };

    // 3. PCK leaf signed the QE report
    p256_verify(&spki_xy(&certs[0]), qe_report_sig, qe_report)
        .context("PCK leaf did not sign the QE report")?;

    // 4. chain verifies to a self-signed Intel SGX Root CA
    let root = certs
        .iter()
        .find(|c| c.tbs_certificate.issuer == c.tbs_certificate.subject)
        .ok_or_else(|| miette::miette!("self-signed root not found in embedded PCK chain"))?;
    let root_subject = format!("{}", root.tbs_certificate.subject);
    if !root_subject.contains(INTEL_SGX_ROOT_CN) {
        bail!("embedded root is not the Intel SGX Root CA: {}", root_subject);
    }
    for cert in &certs {
        let issuer = match certs
            .iter()
            .find(|c| c.tbs_certificate.subject == cert.tbs_certificate.issuer)
        {
            Some(i) => i,
            None => continue,
        };
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&spki_xy(issuer)[..64]);
        let key = VerifyingKey::from_sec1_bytes(&sec1)
            .into_diagnostic()
            .context("parsing issuer P-256 key")?;
        let tbs = cert.tbs_certificate.to_der().into_diagnostic()?;
        let sig = Signature::from_der(cert.signature.raw_bytes())
            .into_diagnostic()
            .context("parsing cert signature")?;
        key.verify(&tbs, &sig)
            .into_diagnostic()
            .with_context(|| format!("PCK chain broken at {}", cert.tbs_certificate.subject))?;
    }

    let rtmrs = [
        hex::encode(&raw[TDX_RTMR0_OFFSET..TDX_RTMR0_OFFSET + TDX_RTMR_LEN]),
        hex::encode(&raw[TDX_RTMR0_OFFSET + TDX_RTMR_LEN..TDX_RTMR0_OFFSET + 2 * TDX_RTMR_LEN]),
        hex::encode(&raw[TDX_RTMR0_OFFSET + 2 * TDX_RTMR_LEN..TDX_RTMR0_OFFSET + 3 * TDX_RTMR_LEN]),
        hex::encode(&raw[TDX_RTMR0_OFFSET + 3 * TDX_RTMR_LEN..TDX_RTMR0_OFFSET + 4 * TDX_RTMR_LEN]),
    ];
    Ok(TdxVerifyResult {
        mrtd: hex::encode(&raw[TDX_MRTD_OFFSET..TDX_MRTD_OFFSET + 48]),
        rtmrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real dstack/Phala TDX quote from the disco preview epoch-1346 snapshot.
    // Validates the full DCAP chain (AK sig → QE binding → PCK leaf → Intel SGX
    // Root CA) and MRTD extraction against known-good values (matches disco-cli).
    #[test]
    fn tdx_quote_verifies() {
        let att: AttestationJson =
            serde_json::from_str(include_str!("testdata/preview-1346.attestation.json")).unwrap();
        let quote_hex = att.quote.expect("attestation should carry a TDX quote");
        let quote_hex = quote_hex.strip_prefix("0x").unwrap_or(&quote_hex);
        let raw = hex::decode(quote_hex).expect("valid hex quote");

        let res = verify_tdx_quote(&raw).expect("Intel TDX DCAP chain must verify");
        assert_eq!(
            res.mrtd,
            "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
            "MRTD must match the known reproducible disco image measurement"
        );
    }
}

// Number of parallel connections for the snapshot download. R2 throttles per
// connection (~10 MB/s) but not per bucket, so N streams give ~N× throughput.
const DL_CONNS: u64 = 16;

// Parallel range download: split the object into DL_CONNS chunks, one blocking
// GET per thread with a Range header, positioned writes (pwrite) into the
// preallocated file. Needs a server that supports byte ranges (R2 does).
fn download_parallel(
    client: &reqwest::blocking::Client,
    url: &str,
    dest: &Path,
    total: u64,
    conns: u64,
) -> miette::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::FileExt;

    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)
            .into_diagnostic()
            .context("creating temp tar file")?;
        f.set_len(total)
            .into_diagnostic()
            .context("preallocating temp tar file")?;
    }

    let chunk = total.div_ceil(conns);
    let mut handles = Vec::new();
    for i in 0..conns {
        let start = i * chunk;
        if start >= total {
            break;
        }
        let end = std::cmp::min(start + chunk, total) - 1;
        let client = client.clone();
        let url = url.to_string();
        let dest = dest.to_path_buf();
        handles.push(std::thread::spawn(move || -> miette::Result<()> {
            // Resilient per-chunk download: on any connection/stream error or a
            // premature EOF, resume the range from the current offset. A 175 GB
            // transfer over a CDN will hit occasional HTTP/2 stream drops.
            const MAX_RETRIES: u32 = 40;
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&dest)
                .into_diagnostic()
                .context("opening temp for positioned write")?;
            let mut off = start;
            let mut attempt = 0u32;
            while off <= end {
                let res: miette::Result<()> = (|| {
                    let mut resp = client
                        .get(&url)
                        .header(reqwest::header::RANGE, format!("bytes={}-{}", off, end))
                        .send()
                        .into_diagnostic()
                        .context("range GET")?
                        .error_for_status()
                        .into_diagnostic()
                        .context("range GET status")?;
                    let mut buf = vec![0u8; 1 << 20];
                    loop {
                        let n = resp
                            .read(&mut buf)
                            .into_diagnostic()
                            .context("reading range body")?;
                        if n == 0 {
                            return Ok(()); // stream ended (maybe early) — checked below
                        }
                        f.write_all_at(&buf[..n], off)
                            .into_diagnostic()
                            .context("positioned write")?;
                        off += n as u64;
                        if off > end {
                            return Ok(());
                        }
                    }
                })();
                if res.is_ok() && off > end {
                    break;
                }
                // error, or clean EOF before the range end → retry from `off`
                attempt += 1;
                if attempt > MAX_RETRIES {
                    return res.and(Err(miette::miette!(
                        "range {}-{} stalled at {} after {} retries",
                        start,
                        end,
                        off,
                        MAX_RETRIES
                    )));
                }
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Ok(())
        }));
    }
    for h in handles {
        h.join()
            .map_err(|_| miette::miette!("download thread panicked"))??;
    }
    Ok(())
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

    // 3. download tarball to a temp file, in parallel (R2 is per-connection
    // throttled). Falls back to single-stream if the server doesn't report a
    // size or support byte ranges.
    let tar_url = format!("{}/{}/{}", base, network, snap);

    let tar_tmp = std::env::temp_dir().join(format!(
        "dolos-disco-{}-{}.tar.gz",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .into_diagnostic()
            .context("reading system time")?
            .as_nanos()
    ));

    let head = client
        .head(&tar_url)
        .send()
        .into_diagnostic()
        .context("HEAD tarball")?
        .error_for_status()
        .into_diagnostic()
        .context("HEAD tarball status")?;
    let total = head.content_length().unwrap_or(0);
    let ranges_ok = head
        .headers()
        .get(reqwest::header::ACCEPT_RANGES)
        .map(|v| v.as_bytes() == b"bytes")
        .unwrap_or(false);

    if total > 0 && ranges_ok {
        eprintln!(
            "downloading {} ({} bytes) with {} parallel connections …",
            snap, total, DL_CONNS
        );
        download_parallel(&client, &tar_url, &tar_tmp, total, DL_CONNS)?;
    } else {
        eprintln!("downloading {} (single stream) …", snap);
        let response = client
            .get(&tar_url)
            .send()
            .into_diagnostic()
            .context("downloading tarball")?
            .error_for_status()
            .into_diagnostic()
            .context("tarball download error")?;
        let progress = feedback.bytes_progress_bar();
        progress.set_length(response.content_length().unwrap_or(0));
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
    }

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

    // 5. verify TEE attestation. Dispatch on format: Intel TDX quote (dstack /
    // Phala) or AMD SEV-SNP report. Both bind REPORT_DATA[:32] = SHA256(content).
    eprintln!("verifying TEE attestation …");
    let attest_bytes = http_get_bytes(&client, &attest_url)?;
    let attest: AttestationJson = serde_json::from_slice(&attest_bytes)
        .into_diagnostic()
        .context("parsing attestation JSON")?;

    let expected_rd = Sha256::digest(content_hash.as_bytes());
    let tee_summary: String;

    if let Some(quote_hex) = attest.quote.as_deref() {
        // Intel TDX (dstack / Phala) — DCAP chain is embedded, no network needed.
        let q = quote_hex.strip_prefix("0x").unwrap_or(quote_hex);
        let raw = hex::decode(q)
            .into_diagnostic()
            .context("decoding TDX quote hex")?;
        if raw.len() < TDX_REPORTDATA_OFFSET + 64 {
            bail!("TDX quote too short: {} bytes", raw.len());
        }
        let actual_rd = &raw[TDX_REPORTDATA_OFFSET..TDX_REPORTDATA_OFFSET + 32];
        if actual_rd != expected_rd.as_slice() {
            bail!(
                "REPORT_DATA mismatch!\n  expected: {}\n  got:      {}",
                hex::encode(expected_rd),
                hex::encode(actual_rd)
            );
        }
        let tdx = verify_tdx_quote(&raw).context("Intel TDX DCAP verification failed")?;
        if verbose {
            eprintln!("  REPORT_DATA[:32] ✓  {}", hex::encode(actual_rd));
            eprintln!("  Intel TDX DCAP quote ✓  (AK + QE report + PCK chain → Intel SGX Root CA)");
            eprintln!("  MRTD:  {}", tdx.mrtd);
            for (i, r) in tdx.rtmrs.iter().enumerate() {
                eprintln!("  RTMR{}: {}", i, r);
            }
        }
        tee_summary = "Intel TDX attestation verified ✓".to_string();
    } else if let Some(report_hex) = attest.report.as_deref() {
        // AMD SEV-SNP.
        let raw = hex::decode(report_hex)
            .into_diagnostic()
            .context("decoding SNP report hex")?;
        if raw.len() < SNP_SIGNATURE_OFFSET + 144 {
            bail!("SNP report too short: {} bytes", raw.len());
        }
        let report = SnpReport(&raw);
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
        // VCEK chain. AMD KDS unavailability is tolerated; invalid crypto is not.
        tee_summary = match verify_vcek_chain(&client, &raw) {
            Ok(result) => {
                if verbose {
                    eprintln!("  AMD {} VCEK chain ✓", result.product);
                    eprintln!("  MEASUREMENT: {}", result.measurement);
                }
                "TEE attestation verified ✓".to_string()
            }
            Err(VcekVerifyError::Unavailable(e)) => {
                if verbose {
                    eprintln!("  VCEK chain skipped: {}", e);
                }
                "content hash verified ✓  (VCEK chain skipped — kds.amd.com unreachable)".to_string()
            }
            Err(VcekVerifyError::Invalid(e)) => return Err(e),
        };
    } else {
        bail!("attestation JSON has neither 'quote' (Intel TDX) nor 'report' (AMD SNP)");
    }

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

    println!("{}", tee_summary);

    Ok(())
}

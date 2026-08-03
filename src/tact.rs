//! NGDP/TACT discovery: the HTTP endpoints a client queries to find out
//! which build is current and which CDN hosts serve its files.
//!
//! Before a client can read anything from a CDN it makes two requests to
//! Blizzard's version server:
//!
//! - `versions_url(region, product)` — which build config/CDN config are
//!   current for each region, e.g. `us`, `eu`, `cn`.
//! - `cdns_url(region, product)` — which hosts and path prefix serve that
//!   product's files for each region.
//!
//! Both responses are pipe-delimited tables in exactly the same
//! `Name!TYPE:size` header format as `.build.info` (see [`crate::config`]),
//! so parsing here builds on [`crate::config::BuildInfo`] rather than
//! reimplementing the table format. The one wrinkle NGDP responses add that
//! `.build.info` never has is `## seqn = <n>` comment lines, which
//! `BuildInfo::parse` skips.
//!
//! Once a CDN host and path are known, [`cdn_file_url`] builds the URL for
//! an individual file. Two addressing schemes are in play: files under
//! `config/` are addressed by the *config file's own hash* (as returned by
//! the `versions` response), while files under `data/` — archives and loose
//! files alike — are addressed by EKey. See [`CdnPathKind`].
//!
//! One important difference from local storage: files served under `data/`
//! on a CDN are **bare BLTE** — just the `BLTE` container, with no 30-byte
//! span header in front of it. Local `Data/data/data.NNN` archives prefix
//! each entry with that span header (see `docs/casc-format.md`); CDN
//! archives and loose files do not. Anything that reads CDN-served bytes
//! needs to hand them to the BLTE decoder directly, not to whatever strips
//! the local span header.

use crate::config::BuildInfo;
use crate::error::{CascError, Result};
use crate::keys::ContentKey;

const MAX_CDN_HOSTS: usize = 8;

/// One row of an NGDP `versions` response: the current build for one
/// region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionEntry {
    /// The region this row applies to, e.g. `"us"`.
    pub region: String,
    /// Hash of the build config file on the CDN, found under
    /// `config/<xx>/<yy>/<hex>` (see [`cdn_file_url`]). Not an [`crate::keys::EncodingKey`]
    /// despite living under `config/`.
    pub build_config: ContentKey,
    /// Hash of the CDN config file, addressed the same way as
    /// `build_config`.
    pub cdn_config: ContentKey,
    /// The `BuildId` column, e.g. `13515`.
    pub build_id: Option<u32>,
    /// The `VersionsName` column, e.g. `"1.23.10.13515"`.
    pub versions_name: Option<String>,
}

/// A parsed NGDP `versions` response: one row per region.
///
/// See [`Versions::parse`] for the format.
#[derive(Debug, Clone)]
pub struct Versions {
    entries: Vec<VersionEntry>,
}

impl Versions {
    /// Parses a `versions` response (the body of a GET to [`versions_url`]).
    ///
    /// This is a [`BuildInfo`] table under the hood; see
    /// [`BuildInfo::parse`] for the shared pipe-delimited format and how
    /// `## seqn = <n>` comment lines are skipped.
    ///
    /// Every row must have a non-empty `Region`, `BuildConfig`, and
    /// `CDNConfig` column with a valid 16-byte hex hash — a row failing any
    /// of these is an error (not skipped), since those three are required
    /// for the row to be usable at all. `BuildId` and `VersionsName` are
    /// optional. `KeyRing` and `ProductConfig` columns are ignored.
    pub fn parse(text: &str) -> Result<Versions> {
        let info = BuildInfo::parse(text)?;
        let mut entries = Vec::with_capacity(info.records().len());
        for record in info.records() {
            let region = record
                .get("Region")
                .ok_or_else(|| CascError::malformed("versions", "record missing 'Region'"))?
                .to_string();
            let build_config_hex = record
                .get("BuildConfig")
                .ok_or_else(|| CascError::malformed("versions", "record missing 'BuildConfig'"))?;
            let build_config = ContentKey::from_hex(build_config_hex)?;
            let cdn_config_hex = record
                .get("CDNConfig")
                .ok_or_else(|| CascError::malformed("versions", "record missing 'CDNConfig'"))?;
            let cdn_config = ContentKey::from_hex(cdn_config_hex)?;
            let build_id = record.get("BuildId").and_then(|s| s.parse().ok());
            let versions_name = record.get("VersionsName").map(str::to_string);

            entries.push(VersionEntry {
                region,
                build_config,
                cdn_config,
                build_id,
                versions_name,
            });
        }
        Ok(Versions { entries })
    }

    /// The row for `region` (e.g. `"us"`), if present.
    pub fn region(&self, region: &str) -> Option<&VersionEntry> {
        self.entries.iter().find(|e| e.region == region)
    }

    /// All parsed rows, in file order.
    pub fn entries(&self) -> &[VersionEntry] {
        &self.entries
    }
}

/// One row of an NGDP `cdns` response: the CDN hosts and path prefix
/// serving a product for one region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnEntry {
    /// The region this row applies to, e.g. `"us"`.
    pub name: String,
    /// The path prefix under each host, e.g. `"tpr/sc1live"`. Combined with
    /// a host and a file hash by [`cdn_file_url`].
    pub path: String,
    /// Candidate hosts, in preference order (as listed in the response's
    /// space-separated `Hosts` column), e.g. `["level3.blizzard.com",
    /// "us.cdn.blizzard.com"]`.
    pub hosts: Vec<String>,
}

/// A parsed NGDP `cdns` response: one row per region.
///
/// See [`Cdns::parse`] for the format.
#[derive(Debug, Clone)]
pub struct Cdns {
    entries: Vec<CdnEntry>,
}

impl Cdns {
    /// Parses a `cdns` response (the body of a GET to [`cdns_url`]).
    ///
    /// This is a [`BuildInfo`] table under the hood; see
    /// [`BuildInfo::parse`] for the shared pipe-delimited format and how
    /// `## seqn = <n>` comment lines are skipped.
    ///
    /// Unlike [`Versions::parse`], individual bad rows aren't fatal: a row
    /// with a missing/empty `Name`, missing/empty `Path`, or an empty
    /// (or absent) `Hosts` column is silently skipped, since a response can
    /// legitimately list regions this product isn't distributed to. It's
    /// only an error if *every* row gets skipped, leaving nothing usable.
    /// `Servers` and `ConfigPath` columns are ignored.
    pub fn parse(text: &str) -> Result<Cdns> {
        let info = BuildInfo::parse(text)?;
        let mut entries = Vec::new();
        for record in info.records() {
            let Some(name) = record.get("Name") else {
                continue;
            };
            let Some(path) = record.get("Path") else {
                continue;
            };
            let mut hosts = Vec::new();
            if let Some(value) = record.get("Hosts") {
                for host in value.split_whitespace() {
                    if hosts.len() >= MAX_CDN_HOSTS {
                        return Err(CascError::LimitExceeded {
                            what: "CDN hosts",
                            limit: MAX_CDN_HOSTS,
                        });
                    }
                    hosts.push(host.to_string());
                }
            }
            if hosts.is_empty() {
                continue;
            }
            entries.push(CdnEntry {
                name: name.to_string(),
                path: path.to_string(),
                hosts,
            });
        }
        if entries.is_empty() {
            return Err(CascError::malformed("cdns", "no usable rows"));
        }
        Ok(Cdns { entries })
    }

    /// The row for `name` (e.g. `"us"`), if present.
    pub fn region(&self, name: &str) -> Option<&CdnEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// All parsed rows, in file order.
    pub fn entries(&self) -> &[CdnEntry] {
        &self.entries
    }
}

/// Builds the URL for a region's `versions` document:
/// `http://<region>.patch.battle.net:1119/<product>/versions`.
pub fn versions_url(region: &str, product: &str) -> String {
    format!("http://{region}.patch.battle.net:1119/{product}/versions")
}

/// Builds the URL for a region's `cdns` document:
/// `http://<region>.patch.battle.net:1119/<product>/cdns`.
pub fn cdns_url(region: &str, product: &str) -> String {
    format!("http://{region}.patch.battle.net:1119/{product}/cdns")
}

/// Validates caller-supplied discovery identifiers before they are placed in
/// an authority or path component by [`versions_url`] / [`cdns_url`].
pub(crate) fn validate_discovery_identifier(value: &str, what: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CascError::malformed(
            what,
            "must contain only 1-64 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

/// Validates the mutable host/path values returned by the plain-HTTP `cdns`
/// endpoint. SC:R is served from Blizzard-owned DNS names; accepting an
/// arbitrary authority here would allow a forged discovery response to turn
/// the reader into an SSRF client, including during pinned opens.
pub(crate) fn validate_cdn_location(hosts: &[String], path: &str) -> Result<()> {
    if hosts.is_empty() {
        return Err(CascError::malformed("CDN hosts", "host list is empty"));
    }
    if hosts.len() > MAX_CDN_HOSTS {
        return Err(CascError::LimitExceeded {
            what: "CDN hosts",
            limit: MAX_CDN_HOSTS,
        });
    }
    for host in hosts {
        let host_lower = host.to_ascii_lowercase();
        let dns_shape = host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
            });
        if !dns_shape || !(host_lower == "blizzard.com" || host_lower.ends_with(".blizzard.com")) {
            return Err(CascError::malformed(
                "CDN host",
                "must be a Blizzard-owned DNS hostname",
            ));
        }
    }

    if path.is_empty()
        || path.len() > 1024
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(CascError::malformed(
            "CDN path",
            "must be a plain relative ASCII path",
        ));
    }
    Ok(())
}

/// Which subtree of a CDN a file hash addresses, per [`cdn_file_url`].
///
/// - `Config`: the file lives under `<cdn_path>/config/` and is addressed
///   by the config file's own hash — the `BuildConfig`/`CDNConfig` hashes
///   from a [`Versions`] row, or a hash found inside a config file (e.g.
///   `encoding`, `root`, `install`).
/// - `Data`: the file lives under `<cdn_path>/data/` and is addressed by
///   EKey, whether it's a loose file or an archive (`.index` requests the
///   archive's index rather than its data — see `index`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnPathKind {
    /// `<cdn_path>/config/<xx>/<yy>/<hash_hex>` — addressed by the config
    /// file's own hash.
    Config,
    /// `<cdn_path>/data/<xx>/<yy>/<hash_hex>` — addressed by EKey.
    Data,
}

/// Builds the URL for a single file on a CDN:
/// `http://<host>/<cdn_path>/<kind>/<xx>/<yy>/<hash_hex>`, with a `.index`
/// suffix appended when `index` is set.
///
/// `xx`/`yy` are the first two byte-pairs (four hex chars) of `hash_hex`,
/// matching the local `config/`/`data/` sharding scheme (see
/// [`crate::config::BuildInfoRecord::build_key`]). The hash must be exactly
/// 32 ASCII hexadecimal characters. This rejects malformed archive names
/// from CDN configs rather than slicing them and panicking.
pub fn cdn_file_url(
    host: &str,
    cdn_path: &str,
    kind: CdnPathKind,
    hash_hex: &str,
    index: bool,
) -> Result<String> {
    if hash_hex.len() != ContentKey::LENGTH * 2 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CascError::malformed(
            "CDN content address",
            "hash must be exactly 32 hexadecimal characters",
        ));
    }
    let kind_str = match kind {
        CdnPathKind::Config => "config",
        CdnPathKind::Data => "data",
    };
    let suffix = if index { ".index" } else { "" };
    Ok(format!(
        "http://{host}/{cdn_path}/{kind_str}/{}/{}/{hash_hex}{suffix}",
        &hash_hex[0..2],
        &hash_hex[2..4],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_ok::assert_ok;

    const VERSIONS_SAMPLE: &str = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16|KeyRing!HEX:16|BuildId!DEC:4|VersionsName!String:0|ProductConfig!HEX:16\n\
## seqn = 2575619\n\
us|864772b9ff94f6d372aa4ee90ee2f8ab|bd4a0f876fdbf39666f0fae661e54974||13515|1.23.10.13515|c61fc45c039ea8dfd98febbc5b6e73b8\n\
eu|864772b9ff94f6d372aa4ee90ee2f8ab|bd4a0f876fdbf39666f0fae661e54974||13515|1.23.10.13515|c61fc45c039ea8dfd98febbc5b6e73b8\n\
cn|4f29e696409f060a27d9bb716a87ab2b|bd4a0f876fdbf39666f0fae661e54974||11269|1.23.10.11269|c61fc45c039ea8dfd98febbc5b6e73b8\n";

    const CDNS_SAMPLE: &str = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0|Servers!STRING:0|ConfigPath!STRING:0\n\
## seqn = 3437954\n\
us|tpr/sc1live|level3.blizzard.com us.cdn.blizzard.com|http://level3.blizzard.com/?maxhosts=4 http://us.cdn.blizzard.com/?maxhosts=4 https://level3.ssl.blizzard.com/?maxhosts=4&fallback=1 https://us.cdn.blizzard.com/?maxhosts=4&fallback=1|tpr/configs/data\n";

    // --- Versions ---

    #[test]
    fn versions_parses_real_sample() {
        let versions = assert_ok!(Versions::parse(VERSIONS_SAMPLE));
        assert_eq!(versions.entries().len(), 3);

        let us = versions.region("us").expect("us region present");
        assert_eq!(us.region, "us");
        assert_eq!(
            us.build_config.to_string(),
            "864772b9ff94f6d372aa4ee90ee2f8ab"
        );
        assert_eq!(
            us.cdn_config.to_string(),
            "bd4a0f876fdbf39666f0fae661e54974"
        );
        assert_eq!(us.build_id, Some(13515));
        assert_eq!(us.versions_name.as_deref(), Some("1.23.10.13515"));
    }

    #[test]
    fn versions_cn_row_differs() {
        let versions = assert_ok!(Versions::parse(VERSIONS_SAMPLE));
        let cn = versions.region("cn").expect("cn region present");
        assert_eq!(
            cn.build_config.to_string(),
            "4f29e696409f060a27d9bb716a87ab2b"
        );
        assert_eq!(cn.build_id, Some(11269));
        assert_eq!(cn.versions_name.as_deref(), Some("1.23.10.11269"));
        // Shares the same CDN config as us/eu.
        assert_eq!(
            cn.cdn_config.to_string(),
            "bd4a0f876fdbf39666f0fae661e54974"
        );
    }

    #[test]
    fn versions_region_hit_and_miss() {
        let versions = assert_ok!(Versions::parse(VERSIONS_SAMPLE));
        assert!(versions.region("eu").is_some());
        assert!(versions.region("kr").is_none());
    }

    #[test]
    fn versions_missing_build_config_errors() {
        let text = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\n\
                     us||bd4a0f876fdbf39666f0fae661e54974\n";
        assert!(Versions::parse(text).is_err());
    }

    #[test]
    fn versions_missing_cdn_config_errors() {
        let text = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\n\
                     us|864772b9ff94f6d372aa4ee90ee2f8ab|\n";
        assert!(Versions::parse(text).is_err());
    }

    #[test]
    fn versions_missing_region_errors() {
        let text = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\n\
                     |864772b9ff94f6d372aa4ee90ee2f8ab|bd4a0f876fdbf39666f0fae661e54974\n";
        assert!(Versions::parse(text).is_err());
    }

    #[test]
    fn versions_invalid_hex_errors() {
        let text = "Region!STRING:0|BuildConfig!HEX:16|CDNConfig!HEX:16\n\
                     us|not-valid-hex|bd4a0f876fdbf39666f0fae661e54974\n";
        assert!(Versions::parse(text).is_err());
    }

    // --- Cdns ---

    #[test]
    fn cdns_parses_real_sample() {
        let cdns = assert_ok!(Cdns::parse(CDNS_SAMPLE));
        assert_eq!(cdns.entries().len(), 1);

        let us = cdns.region("us").expect("us region present");
        assert_eq!(us.name, "us");
        assert_eq!(us.path, "tpr/sc1live");
        assert_eq!(us.hosts, vec!["level3.blizzard.com", "us.cdn.blizzard.com"]);
    }

    #[test]
    fn cdns_region_hit_and_miss() {
        let cdns = assert_ok!(Cdns::parse(CDNS_SAMPLE));
        assert!(cdns.region("us").is_some());
        assert!(cdns.region("eu").is_none());
    }

    #[test]
    fn cdns_hosts_splitting_preserves_order() {
        let text = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\n\
                     eu|tpr/sc1live|a.cdn.example b.cdn.example c.cdn.example\n";
        let cdns = assert_ok!(Cdns::parse(text));
        let eu = cdns.region("eu").unwrap();
        assert_eq!(
            eu.hosts,
            vec!["a.cdn.example", "b.cdn.example", "c.cdn.example"]
        );
    }

    #[test]
    fn cdns_rejects_excessive_host_fallbacks() {
        let hosts = (0..=MAX_CDN_HOSTS)
            .map(|i| format!("cdn{i}.blizzard.com"))
            .collect::<Vec<_>>()
            .join(" ");
        let text = format!("Name!STRING:0|Path!STRING:0|Hosts!STRING:0\nus|tpr/sc1live|{hosts}\n");
        assert!(matches!(
            Cdns::parse(&text),
            Err(CascError::LimitExceeded {
                what: "CDN hosts",
                ..
            })
        ));
    }

    #[test]
    fn cdns_skips_row_with_empty_path() {
        let text = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\n\
                     kr||host.example\n\
                     us|tpr/sc1live|host.example\n";
        let cdns = assert_ok!(Cdns::parse(text));
        assert_eq!(cdns.entries().len(), 1);
        assert!(cdns.region("kr").is_none());
        assert!(cdns.region("us").is_some());
    }

    #[test]
    fn cdns_skips_row_with_no_hosts() {
        let text = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\n\
                     kr|tpr/sc1live|\n\
                     us|tpr/sc1live|host.example\n";
        let cdns = assert_ok!(Cdns::parse(text));
        assert_eq!(cdns.entries().len(), 1);
        assert!(cdns.region("kr").is_none());
    }

    #[test]
    fn cdns_all_rows_skipped_is_error() {
        let text = "Name!STRING:0|Path!STRING:0|Hosts!STRING:0\n\
                     kr||\n\
                     tw|tpr/sc1live|\n";
        assert!(Cdns::parse(text).is_err());
    }

    // --- URLs ---

    #[test]
    fn versions_url_construction() {
        assert_eq!(
            versions_url("us", "s1"),
            "http://us.patch.battle.net:1119/s1/versions"
        );
    }

    #[test]
    fn cdns_url_construction() {
        assert_eq!(
            cdns_url("eu", "s1"),
            "http://eu.patch.battle.net:1119/s1/cdns"
        );
    }

    #[test]
    fn cdn_file_url_config_no_index() {
        let url = cdn_file_url(
            "us.cdn.blizzard.com",
            "tpr/sc1live",
            CdnPathKind::Config,
            "864772b9ff94f6d372aa4ee90ee2f8ab",
            false,
        )
        .unwrap();
        assert_eq!(
            url,
            "http://us.cdn.blizzard.com/tpr/sc1live/config/86/47/864772b9ff94f6d372aa4ee90ee2f8ab"
        );
    }

    #[test]
    fn cdn_file_url_data_with_index() {
        let url = cdn_file_url(
            "level3.blizzard.com",
            "tpr/sc1live",
            CdnPathKind::Data,
            "b135dde729b026904eeb4b7e76332750",
            true,
        )
        .unwrap();
        assert_eq!(
            url,
            "http://level3.blizzard.com/tpr/sc1live/data/b1/35/b135dde729b026904eeb4b7e76332750.index"
        );
    }

    #[test]
    fn cdn_file_url_rejects_malformed_hashes() {
        for hash in ["", "abcd", "z64772b9ff94f6d372aa4ee90ee2f8ab"] {
            let err = cdn_file_url("host", "path", CdnPathKind::Data, hash, false).unwrap_err();
            assert!(matches!(err, CascError::Malformed { .. }));
        }
    }

    #[test]
    fn discovery_identifiers_reject_url_syntax() {
        for value in ["", "us.example", "us@127.0.0.1", "../s1", "s1/versions"] {
            assert!(validate_discovery_identifier(value, "test identifier").is_err());
        }
        assert!(validate_discovery_identifier("s1_beta-2", "test identifier").is_ok());
    }

    #[test]
    fn cdn_location_rejects_untrusted_authorities_and_paths() {
        assert!(
            validate_cdn_location(
                &[
                    "level3.blizzard.com".to_string(),
                    "us.cdn.blizzard.com".to_string()
                ],
                "tpr/sc1live"
            )
            .is_ok()
        );
        for host in [
            "127.0.0.1",
            "localhost",
            "blizzard.com.attacker.test",
            "user@blizzard.com",
        ] {
            assert!(validate_cdn_location(&[host.to_string()], "tpr/sc1live").is_err());
        }
        for path in [
            "",
            "/tpr/sc1live",
            "tpr/../private",
            "tpr//sc1live",
            "tpr?x/y",
        ] {
            assert!(validate_cdn_location(&["cdn.blizzard.com".to_string()], path).is_err());
        }
    }
}

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
            let hosts: Vec<String> = record
                .get("Hosts")
                .map(|h| h.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default();
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
/// [`crate::config::BuildInfoRecord::build_key`]). `hash_hex` must be a
/// lowercase hex string at least 4 characters long — this function does no
/// validation of it beyond slicing, since callers already hold a typed key
/// ([`ContentKey`] or [`crate::keys::EncodingKey`]) and are expected to
/// format it themselves (e.g. via `Display`).
pub fn cdn_file_url(
    host: &str,
    cdn_path: &str,
    kind: CdnPathKind,
    hash_hex: &str,
    index: bool,
) -> String {
    let kind_str = match kind {
        CdnPathKind::Config => "config",
        CdnPathKind::Data => "data",
    };
    let suffix = if index { ".index" } else { "" };
    format!(
        "http://{host}/{cdn_path}/{kind_str}/{}/{}/{hash_hex}{suffix}",
        &hash_hex[0..2],
        &hash_hex[2..4],
    )
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
        );
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
        );
        assert_eq!(
            url,
            "http://level3.blizzard.com/tpr/sc1live/data/b1/35/b135dde729b026904eeb4b7e76332750.index"
        );
    }
}

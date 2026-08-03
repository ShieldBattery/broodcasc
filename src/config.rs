//! Parsers for the plain-text configuration formats used by CASC local
//! storage: `.build.info` and the build config it points at.
//!
//! `.build.info` lives at the root of a storage and is a pipe-delimited table
//! listing the builds installed for a product; each row's `Build Key` is the
//! CKey of a build config file living under `config/`. That build config is
//! itself a simple `key = value` text file whose values are (mostly)
//! whitespace-separated pairs of `CKey EKey` hashes pointing at the encoding
//! file, install manifest, root file, and so on.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{CascError, Result};
use crate::keys::{ContentKey, EncodingKey};

/// A parsed `.build.info` file: a pipe-delimited table of installed builds.
///
/// See [`BuildInfo::parse`] for the format.
#[derive(Debug, Clone)]
pub struct BuildInfo {
    records: Vec<BuildInfoRecord>,
}

/// One row of a [`BuildInfo`] table, addressable by column name.
#[derive(Debug, Clone)]
pub struct BuildInfoRecord {
    columns: Arc<[String]>,
    values: Vec<Option<String>>,
}

impl BuildInfo {
    /// Parses a `.build.info` file.
    ///
    /// The first non-empty line is a header of `|`-separated columns, each
    /// formatted `Name!TYPE:size` (the `!TYPE:size` suffix is discarded;
    /// only `Name` is kept). Every
    /// following non-empty line is a record with `|`-separated values in the
    /// same order as the header; an empty value is treated as absent
    /// (`None`) rather than an empty string. Trailing empty lines and CRLF
    /// line endings are tolerated.
    ///
    /// Lines whose trimmed form starts with `#` are skipped entirely,
    /// wherever they appear — before the header or between records.
    /// `.build.info` itself never contains these, but the same pipe-delimited
    /// table format is also used by NGDP's `versions`/`cdns` HTTP responses,
    /// which intersperse `## seqn = <n>` comment lines; skipping them here
    /// lets this same parser handle those responses directly.
    ///
    /// Fails on empty input, a header column missing the `!` type
    /// separator, or a record with more fields than the header has columns
    /// (fewer fields is fine — the missing trailing fields become `None`).
    pub fn parse(text: &str) -> Result<BuildInfo> {
        let mut lines = text.lines().filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        });

        let header = lines
            .next()
            .ok_or_else(|| CascError::malformed("build info", "empty input"))?;

        let mut columns = Vec::new();
        for col in header.split('|') {
            if !col.contains('!') {
                return Err(CascError::malformed(
                    "build info",
                    format!("header column missing '!': {col:?}"),
                ));
            }
            let name = col.split('!').next().unwrap_or(col).trim();
            columns.push(name.to_string());
        }
        let columns: Arc<[String]> = columns.into();

        let mut records = Vec::new();
        for line in lines {
            let fields: Vec<&str> = line.split('|').collect();
            if fields.len() > columns.len() {
                return Err(CascError::malformed(
                    "build info",
                    format!(
                        "record has {} fields but header has {}",
                        fields.len(),
                        columns.len()
                    ),
                ));
            }
            let values = (0..columns.len())
                .map(|i| {
                    fields
                        .get(i)
                        .copied()
                        .filter(|v| !v.is_empty())
                        .map(str::to_string)
                })
                .collect();
            records.push(BuildInfoRecord {
                columns: columns.clone(),
                values,
            });
        }

        Ok(BuildInfo { records })
    }

    /// All parsed records, in file order.
    pub fn records(&self) -> &[BuildInfoRecord] {
        &self.records
    }

    /// The first record whose `Active` column is `"1"`, if any.
    ///
    /// This is the build the client would currently launch; a storage can
    /// list builds for other products/regions that aren't active.
    pub fn active_record(&self) -> Option<&BuildInfoRecord> {
        self.records.iter().find(|r| r.get("Active") == Some("1"))
    }
}

impl BuildInfoRecord {
    /// The value in the named column, or `None` if the column doesn't exist,
    /// the record didn't have enough fields to reach it, or the value was
    /// empty.
    pub fn get(&self, column: &str) -> Option<&str> {
        let index = self.columns.iter().position(|c| c == column)?;
        self.values.get(index)?.as_deref()
    }

    /// The `Build Key` column: the CKey (MD5) of this record's build config
    /// file, found under `config/<xx>/<yy>/<hex>` where `xx`/`yy` are the
    /// first two byte-pairs of the hex string.
    pub fn build_key(&self) -> Result<ContentKey> {
        let hex = self
            .get("Build Key")
            .ok_or_else(|| CascError::malformed("build info", "record missing 'Build Key'"))?;
        ContentKey::from_hex(hex)
    }

    /// The `Version` column, e.g. `"1.23.10.13515"`.
    pub fn version(&self) -> Option<&str> {
        self.get("Version")
    }

    /// The `Product` column.
    pub fn product(&self) -> Option<&str> {
        self.get("Product")
    }

    /// The `Branch` column, e.g. `"us"`.
    pub fn branch(&self) -> Option<&str> {
        self.get("Branch")
    }
}

/// A parsed build config file: `key = value` pairs pointing at the other
/// files that make up a build (encoding table, install manifest, root file,
/// ...).
///
/// See [`BuildConfig::parse`] for the format.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    entries: HashMap<String, String>,
}

impl BuildConfig {
    /// Parses a build config file.
    ///
    /// Each non-blank, non-comment line is `key = value`; `#` starts a
    /// comment (only recognized at the start of a line, after trimming
    /// whitespace). Many values are whitespace-separated pairs of hashes:
    /// the first is a [`ContentKey`] (CKey, the MD5 of the decoded file) and
    /// the second, where present, is the [`EncodingKey`] (EKey, the MD5 of
    /// the BLTE-encoded file, directly usable to locate it in local
    /// indices). `root` is the odd one out and has only a CKey, since the
    /// root file must be looked up through the encoding table like any
    /// other content.
    pub fn parse(text: &str) -> Result<BuildConfig> {
        let mut entries = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                CascError::malformed("build config", format!("line missing '=': {line:?}"))
            })?;
            entries.insert(key.trim().to_string(), value.trim().to_string());
        }
        Ok(BuildConfig { entries })
    }

    /// The raw value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// The `root` key: the CKey of the root file. Must be resolved through
    /// the encoding table to find the EKey needed to actually read it.
    pub fn root(&self) -> Result<ContentKey> {
        let hex = self
            .get("root")
            .ok_or_else(|| CascError::malformed("build config", "missing 'root'"))?;
        ContentKey::from_hex(hex)
    }

    /// The `encoding` key: `(CKey, EKey)` of the encoding file itself.
    pub fn encoding(&self) -> Result<(ContentKey, EncodingKey)> {
        let (ckey_hex, ekey_hex) = self.two_hashes("encoding")?;
        Ok((
            ContentKey::from_hex(ckey_hex)?,
            EncodingKey::from_hex(ekey_hex)?,
        ))
    }

    /// The `encoding-size` key: `(decoded size, encoded size)` in bytes of
    /// the encoding file.
    pub fn encoding_size(&self) -> Option<(u64, u64)> {
        let value = self.get("encoding-size")?;
        let mut parts = value.split_whitespace();
        let decoded = parts.next()?.parse().ok()?;
        let encoded = parts.next()?.parse().ok()?;
        Some((decoded, encoded))
    }

    /// The `install` key: the install manifest's CKey, with its EKey if
    /// present (some build configs only list the CKey).
    pub fn install(&self) -> Option<(ContentKey, Option<EncodingKey>)> {
        let value = self.get("install")?;
        let mut parts = value.split_whitespace();
        let ckey = ContentKey::from_hex(parts.next()?).ok()?;
        let ekey = parts.next().and_then(|hex| EncodingKey::from_hex(hex).ok());
        Some((ckey, ekey))
    }

    /// The `build-uid` key, e.g. `"s1"`.
    pub fn build_uid(&self) -> Option<&str> {
        self.get("build-uid")
    }

    /// The `build-name` key, e.g. `"1.23.10.13515-retail"`.
    pub fn build_name(&self) -> Option<&str> {
        self.get("build-name")
    }

    /// Splits a two-hash value (`"<ckey hex> <ekey hex>"`) for `key`,
    /// erroring if the key is missing or doesn't have both hashes.
    fn two_hashes(&self, key: &'static str) -> Result<(&str, &str)> {
        let value = self
            .get(key)
            .ok_or_else(|| CascError::malformed("build config", format!("missing '{key}'")))?;
        let mut parts = value.split_whitespace();
        let ckey_hex = parts.next().ok_or_else(|| {
            CascError::malformed("build config", format!("'{key}' has no content key"))
        })?;
        let ekey_hex = parts.next().ok_or_else(|| {
            CascError::malformed("build config", format!("'{key}' has no encoding key"))
        })?;
        Ok((ckey_hex, ekey_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_ok::assert_ok;
    use proptest::prelude::*;

    const BUILD_INFO_SAMPLE: &str = "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Install Key!HEX:16|IM Size!DEC:4|CDN Path!STRING:0|CDN Hosts!STRING:0|CDN Servers!STRING:0|Tags!STRING:0|Armadillo!STRING:0|Last Activated!STRING:0|Version!STRING:0|KeyRing!HEX:16|Product!STRING:0\nus|1|864772b9ff94f6d372aa4ee90ee2f8ab|bd4a0f876fdbf39666f0fae661e54974|||tpr/sc1live|level3.blizzard.com us.cdn.blizzard.com|http://...|Windows noigr...|||1.23.10.13515||\n";

    const BUILD_CONFIG_SAMPLE: &str = "\
# Build Configuration

root = b96213f265684e16db5a8552eba1be09
install = 507094afe0cfb221bcd106f26e288cfa 311e6a69ea379077313e68b06d9126ed
install-size = 105144 100737
download = 45886a5df9c96d8d5ab6b46a93f60680 f04fd2ace1b4b204eb0b9baf05678e80
download-size = 1093564 948966
size = 996dba1b304873d353413d015ec54272 958428bb9ce4416ccfafde3b961a830f
size-size = 705785 616121
encoding = 6f0a25d319069d1b09bc4034820e5ae0 b135dde729b026904eeb4b7e76332750
encoding-size = 2757673 2757842
patch-index = df4c0ae0d32fe2a538936d2956b8ac09 55b3cbccbdf39e72afb934250933f6d7
patch-index-size = 5598 4805
patch = 155d14754816b49d2a6914f37122a718
patch-size = 9261
patch-config = 44c6c6219e2d1e94b9e2b815eddd0579
build-name = 1.23.10.13515-retail
build-uid = s1
build-product = StarCraft1
build-comments = prod build for new 2025 wildcard cert
build-playbuild-installer = ngdptool_casc2
";

    // --- BuildInfo ---

    #[test]
    fn build_info_parses_real_sample() {
        let info = assert_ok!(BuildInfo::parse(BUILD_INFO_SAMPLE));
        assert_eq!(info.records().len(), 1);

        let record = &info.records()[0];
        assert_eq!(record.branch(), Some("us"));
        assert_eq!(record.get("Active"), Some("1"));
        assert_eq!(record.version(), Some("1.23.10.13515"));
        assert_eq!(
            record.build_key().unwrap().to_string(),
            "864772b9ff94f6d372aa4ee90ee2f8ab"
        );
        assert_eq!(
            record.get("CDN Hosts"),
            Some("level3.blizzard.com us.cdn.blizzard.com")
        );
    }

    #[test]
    fn build_info_empty_values_are_none() {
        let info = assert_ok!(BuildInfo::parse(BUILD_INFO_SAMPLE));
        let record = &info.records()[0];
        // Install Key, IM Size, Armadillo, Last Activated, KeyRing, Product
        // are all empty in the sample.
        assert_eq!(record.get("Install Key"), None);
        assert_eq!(record.get("Armadillo"), None);
        assert_eq!(record.product(), None);
    }

    #[test]
    fn build_info_missing_column_is_none() {
        let info = assert_ok!(BuildInfo::parse(BUILD_INFO_SAMPLE));
        let record = &info.records()[0];
        assert_eq!(record.get("Nonexistent"), None);
    }

    #[test]
    fn build_info_active_record_selection() {
        let text = "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16\n\
                     eu|0|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                     us|1|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
                     kr|0|cccccccccccccccccccccccccccccccc\n";
        let info = assert_ok!(BuildInfo::parse(text));
        assert_eq!(info.records().len(), 3);
        let active = info.active_record().expect("should have an active record");
        assert_eq!(active.branch(), Some("us"));
        assert_eq!(
            active.build_key().unwrap().to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn build_info_no_active_record() {
        let text = "Branch!STRING:0|Active!DEC:1\neu|0\n";
        let info = assert_ok!(BuildInfo::parse(text));
        assert!(info.active_record().is_none());
    }

    #[test]
    fn build_info_record_with_fewer_fields_than_header() {
        let text = "Branch!STRING:0|Active!DEC:1|Build Key!HEX:16\nus|1\n";
        let info = assert_ok!(BuildInfo::parse(text));
        let record = &info.records()[0];
        assert_eq!(record.branch(), Some("us"));
        assert_eq!(record.get("Active"), Some("1"));
        assert_eq!(record.get("Build Key"), None);
        assert!(record.build_key().is_err());
    }

    #[test]
    fn build_info_tolerates_trailing_blank_lines_and_crlf() {
        let text = "Branch!STRING:0|Active!DEC:1\r\nus|1\r\n\r\n\r\n";
        let info = assert_ok!(BuildInfo::parse(text));
        assert_eq!(info.records().len(), 1);
        assert_eq!(info.records()[0].branch(), Some("us"));
    }

    #[test]
    fn build_info_skips_seqn_comment_line() {
        let text = "Branch!STRING:0|Active!DEC:1\n## seqn = 11111\nus|1\n";
        let info = assert_ok!(BuildInfo::parse(text));
        assert_eq!(info.records().len(), 1);
        assert_eq!(info.records()[0].branch(), Some("us"));
    }

    #[test]
    fn build_info_rejects_empty_input() {
        assert!(BuildInfo::parse("").is_err());
        assert!(BuildInfo::parse("\n\n\r\n").is_err());
    }

    #[test]
    fn build_info_rejects_header_missing_bang() {
        let text = "Branch|Active!DEC:1\nus|1\n";
        assert!(BuildInfo::parse(text).is_err());
    }

    #[test]
    fn build_info_rejects_record_with_too_many_fields() {
        let text = "Branch!STRING:0|Active!DEC:1\nus|1|extra\n";
        assert!(BuildInfo::parse(text).is_err());
    }

    // --- BuildConfig ---

    #[test]
    fn build_config_parses_real_sample() {
        let config = assert_ok!(BuildConfig::parse(BUILD_CONFIG_SAMPLE));

        assert_eq!(
            config.root().unwrap().to_string(),
            "b96213f265684e16db5a8552eba1be09"
        );

        let (ckey, ekey) = config.encoding().unwrap();
        assert_eq!(ckey.to_string(), "6f0a25d319069d1b09bc4034820e5ae0");
        assert_eq!(ekey.to_string(), "b135dde729b026904eeb4b7e76332750");

        assert_eq!(config.encoding_size(), Some((2757673, 2757842)));
        assert_eq!(config.build_uid(), Some("s1"));
        assert_eq!(config.build_name(), Some("1.23.10.13515-retail"));

        let (install_ckey, install_ekey) = config.install().unwrap();
        assert_eq!(install_ckey.to_string(), "507094afe0cfb221bcd106f26e288cfa");
        assert_eq!(
            install_ekey.unwrap().to_string(),
            "311e6a69ea379077313e68b06d9126ed"
        );

        assert_eq!(config.get("build-product"), Some("StarCraft1"));
        assert_eq!(
            config.get("build-comments"),
            Some("prod build for new 2025 wildcard cert")
        );
    }

    #[test]
    fn build_config_ignores_comments_and_blanks() {
        let text =
            "# comment\n\n  # indented comment\n\nroot = b96213f265684e16db5a8552eba1be09\n\n";
        let config = assert_ok!(BuildConfig::parse(text));
        assert_eq!(config.get("root"), Some("b96213f265684e16db5a8552eba1be09"));
        assert_eq!(config.entries.len(), 1);
    }

    #[test]
    fn build_config_crlf() {
        let text = "root = b96213f265684e16db5a8552eba1be09\r\nbuild-uid = s1\r\n";
        let config = assert_ok!(BuildConfig::parse(text));
        assert_eq!(config.build_uid(), Some("s1"));
    }

    #[test]
    fn build_config_install_with_only_ckey() {
        let text = "install = 507094afe0cfb221bcd106f26e288cfa\n";
        let config = assert_ok!(BuildConfig::parse(text));
        let (ckey, ekey) = config.install().unwrap();
        assert_eq!(ckey.to_string(), "507094afe0cfb221bcd106f26e288cfa");
        assert_eq!(ekey, None);
    }

    #[test]
    fn build_config_missing_keys_are_none_or_err() {
        let config = assert_ok!(BuildConfig::parse("build-uid = s1\n"));
        assert!(config.root().is_err());
        assert!(config.encoding().is_err());
        assert_eq!(config.encoding_size(), None);
        assert_eq!(config.install(), None);
        assert_eq!(config.build_name(), None);
    }

    #[test]
    fn build_config_malformed_hex_errors() {
        let config = assert_ok!(BuildConfig::parse("root = not-valid-hex\n"));
        assert!(config.root().is_err());

        let config = assert_ok!(BuildConfig::parse("encoding = not-valid-hex alsobad\n"));
        assert!(config.encoding().is_err());
    }

    #[test]
    fn build_config_encoding_missing_second_hash_errors() {
        let config = assert_ok!(BuildConfig::parse(
            "encoding = 6f0a25d319069d1b09bc4034820e5ae0\n"
        ));
        assert!(config.encoding().is_err());
    }

    #[test]
    fn build_config_rejects_line_without_equals() {
        assert!(BuildConfig::parse("this line has no equals sign\n").is_err());
    }

    // --- Property tests ---

    fn config_key_char() -> impl Strategy<Value = char> {
        prop_oneof![Just('-'), (b'a'..=b'z').prop_map(|b| b as char)]
    }

    fn config_key() -> impl Strategy<Value = String> {
        proptest::collection::vec(config_key_char(), 1..12).prop_map(|cs| cs.into_iter().collect())
    }

    /// Visible, non-whitespace printable ASCII: already "trimmed" by
    /// construction (no leading/trailing whitespace to strip), so the
    /// round-trip can compare directly against what was generated.
    fn config_value() -> impl Strategy<Value = String> {
        proptest::collection::vec((0x21u8..=0x7eu8).prop_map(|b| b as char), 1..16)
            .prop_map(|cs| cs.into_iter().collect::<String>())
            .prop_filter("not a comment", |v: &String| !v.starts_with('#'))
    }

    /// Unique-by-key list of `(key, value)` pairs for [`BuildConfig`].
    fn config_entries_strategy() -> impl Strategy<Value = Vec<(String, String)>> {
        proptest::collection::vec((config_key(), config_value()), 1..12).prop_map(|entries| {
            let mut seen = std::collections::HashSet::new();
            entries
                .into_iter()
                .filter(|(k, _)| seen.insert(k.clone()))
                .collect()
        })
    }

    fn info_col_name() -> impl Strategy<Value = String> {
        proptest::collection::vec((b'a'..=b'z').prop_map(|b| b as char), 1..8)
            .prop_map(|cs| cs.into_iter().collect())
    }

    /// Printable ASCII excluding `|` (the field separator) and newlines
    /// (already excluded by the printable range). Excludes values starting
    /// with `#`: if such a value lands in a record's first column, the
    /// serialized line itself would start with `#` and `BuildInfo::parse`
    /// would (correctly) skip it as a comment line, which would break the
    /// roundtrip below — not a bug in the parser, just untestable input for
    /// this particular strategy.
    fn info_value() -> impl Strategy<Value = String> {
        proptest::collection::vec(
            (0x20u8..=0x7eu8)
                .prop_filter("no pipe", |&b| b != b'|')
                .prop_map(|b| b as char),
            1..12,
        )
        .prop_map(|cs| cs.into_iter().collect::<String>())
        .prop_filter("not a comment", |v: &String| !v.starts_with('#'))
    }

    /// At least 2 unique column names, so a serialized record line always
    /// contains at least one `|` and can never be mistaken for a blank line.
    fn info_columns_strategy() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec(info_col_name(), 2..6)
            .prop_map(|cols| {
                let mut seen = std::collections::HashSet::new();
                cols.into_iter()
                    .filter(|c| seen.insert(c.clone()))
                    .collect::<Vec<_>>()
            })
            .prop_filter("need >= 2 unique columns", |cols: &Vec<String>| {
                cols.len() >= 2
            })
    }

    fn build_info_strategy() -> impl Strategy<Value = (Vec<String>, Vec<Vec<Option<String>>>)> {
        info_columns_strategy().prop_flat_map(|cols| {
            let n = cols.len();
            (
                Just(cols),
                proptest::collection::vec(
                    proptest::collection::vec(proptest::option::of(info_value()), n),
                    1..6,
                ),
            )
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Serializing arbitrary unique `key = value` pairs and parsing them
        /// back via [`BuildConfig::parse`] must reproduce every value.
        #[test]
        fn prop_roundtrip_build_config(entries in config_entries_strategy()) {
            let mut text = String::new();
            for (k, v) in &entries {
                text.push_str(&format!("{k} = {v}\n"));
            }
            let config = BuildConfig::parse(&text).unwrap();
            for (k, v) in &entries {
                prop_assert_eq!(config.get(k), Some(v.as_str()));
            }
        }

        /// Serializing an arbitrary header + records table and parsing it
        /// back via [`BuildInfo::parse`] must reproduce every column value
        /// (with empty values mapping to `None`), plus the record count.
        #[test]
        fn prop_roundtrip_build_info((columns, records) in build_info_strategy()) {
            let header = columns
                .iter()
                .map(|c| format!("{c}!STRING:0"))
                .collect::<Vec<_>>()
                .join("|");
            let mut text = header;
            text.push('\n');
            for record in &records {
                let line = record
                    .iter()
                    .map(|v| v.clone().unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("|");
                text.push_str(&line);
                text.push('\n');
            }

            let info = BuildInfo::parse(&text).unwrap();
            prop_assert_eq!(info.records().len(), records.len());
            for (rec, expected) in info.records().iter().zip(&records) {
                for (col, val) in columns.iter().zip(expected) {
                    prop_assert_eq!(rec.get(col), val.as_deref());
                }
            }
        }

        /// Neither `BuildConfig::parse` nor `BuildInfo::parse` should ever
        /// panic, no matter what (lossily-decoded) bytes they're fed.
        #[test]
        fn prop_no_panic_arbitrary_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let s = String::from_utf8_lossy(&data);
            let _ = BuildConfig::parse(&s);
            let _ = BuildInfo::parse(&s);
        }

        /// Flipping a handful of bytes in otherwise-valid config/info files
        /// (lossily re-decoded to UTF-8) should never panic.
        #[test]
        fn prop_no_panic_flipped_bytes(
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
        ) {
            let mut data = BUILD_CONFIG_SAMPLE.as_bytes().to_vec();
            for (pos, xor) in &flips {
                if !data.is_empty() {
                    let idx = pos % data.len();
                    data[idx] ^= xor | 1;
                }
            }
            let s = String::from_utf8_lossy(&data).into_owned();
            let _ = BuildConfig::parse(&s);

            let mut data2 = BUILD_INFO_SAMPLE.as_bytes().to_vec();
            for (pos, xor) in &flips {
                if !data2.is_empty() {
                    let idx = pos % data2.len();
                    data2[idx] ^= xor | 1;
                }
            }
            let s2 = String::from_utf8_lossy(&data2).into_owned();
            let _ = BuildInfo::parse(&s2);
        }

        /// Truncating otherwise-valid config/info files to an arbitrary
        /// length should never panic.
        #[test]
        fn prop_no_panic_truncated(trunc_len in any::<usize>()) {
            let data = BUILD_CONFIG_SAMPLE.as_bytes();
            let len = trunc_len % (data.len() + 1);
            let s = String::from_utf8_lossy(&data[..len]).into_owned();
            let _ = BuildConfig::parse(&s);

            let data2 = BUILD_INFO_SAMPLE.as_bytes();
            let len2 = trunc_len % (data2.len() + 1);
            let s2 = String::from_utf8_lossy(&data2[..len2]).into_owned();
            let _ = BuildInfo::parse(&s2);
        }
    }
}

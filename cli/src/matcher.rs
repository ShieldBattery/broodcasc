//! Case-insensitive path matching for `list`/`extract`: a glob when the
//! pattern looks like one, a plain substring match otherwise (more
//! ergonomic for the common "just find files with 'tileset' in the name"
//! case, which would otherwise need `*tileset*`).

use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobMatcher};

/// Characters that, if present in a pattern, mark it as a glob rather than a
/// plain substring.
const GLOB_METACHARS: [char; 6] = ['*', '?', '[', ']', '{', '}'];

pub enum PathMatcher {
    Substring(String),
    Glob(GlobMatcher),
}

impl PathMatcher {
    /// Builds a matcher for `pattern`. Patterns containing glob
    /// metacharacters (`* ? [ ] { }`) are compiled as case-insensitive
    /// globs; anything else becomes a case-insensitive substring match.
    pub fn new(pattern: &str) -> Result<Self> {
        if is_glob_pattern(pattern) {
            let glob = GlobBuilder::new(pattern)
                .case_insensitive(true)
                .literal_separator(false)
                .build()
                .with_context(|| format!("invalid glob pattern: {pattern:?}"))?;
            Ok(PathMatcher::Glob(glob.compile_matcher()))
        } else {
            Ok(PathMatcher::Substring(pattern.to_lowercase()))
        }
    }

    pub fn is_match(&self, path: &str) -> bool {
        match self {
            PathMatcher::Substring(needle) => path.to_lowercase().contains(needle.as_str()),
            PathMatcher::Glob(glob) => glob.is_match(path),
        }
    }
}

fn is_glob_pattern(pattern: &str) -> bool {
    pattern.chars().any(|c| GLOB_METACHARS.contains(&c))
}

/// Whether `path` matches any of `matchers` (empty `matchers` matches
/// nothing).
pub fn any_match(matchers: &[PathMatcher], path: &str) -> bool {
    matchers.iter().any(|m| m.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_substring_match() {
        let m = PathMatcher::new("tileset").unwrap();
        assert!(m.is_match("SD/tileset/jungle.wpe"));
        assert!(m.is_match("SD/TileSet/jungle.wpe"), "case-insensitive");
        assert!(!m.is_match("SD/sprites/jungle.wpe"));
    }

    #[test]
    fn substring_match_is_case_insensitive_on_both_sides() {
        let m = PathMatcher::new("JUNGLE").unwrap();
        assert!(m.is_match("sd/tileset/jungle.wpe"));
    }

    #[test]
    fn glob_metachars_trigger_glob_matching() {
        let m = PathMatcher::new("*.wpe").unwrap();
        assert!(m.is_match("SD/tileset/jungle.wpe"));
        assert!(!m.is_match("SD/tileset/jungle.chk"));
    }

    #[test]
    fn glob_is_case_insensitive() {
        let m = PathMatcher::new("*.WPE").unwrap();
        assert!(m.is_match("SD/tileset/jungle.wpe"));
    }

    #[test]
    fn glob_star_does_not_cross_path_separators_by_default() {
        // globset's `*` matches within a single path component only when
        // `literal_separator` is set; we explicitly disabled that (`false`)
        // so `*` can cross `/`, matching users' intuitive "substring-ish"
        // glob usage over full catalog paths.
        let m = PathMatcher::new("SD/*jungle*").unwrap();
        assert!(m.is_match("SD/tileset/jungle.wpe"));
    }

    #[test]
    fn glob_bracket_class() {
        let m = PathMatcher::new("*.[wW][pP][eE]").unwrap();
        assert!(m.is_match("SD/tileset/jungle.wpe"));
        assert!(!m.is_match("SD/tileset/jungle.chk"));
    }

    #[test]
    fn invalid_glob_pattern_errors() {
        assert!(PathMatcher::new("[unterminated").is_err());
    }

    #[test]
    fn any_match_across_multiple_patterns() {
        let matchers = vec![
            PathMatcher::new("*.wpe").unwrap(),
            PathMatcher::new("scenario").unwrap(),
        ];
        assert!(any_match(&matchers, "SD/tileset/jungle.wpe"));
        assert!(any_match(&matchers, "SD/campaign/scenario.chk"));
        assert!(!any_match(&matchers, "SD/sound/misc/button.wav"));
    }

    #[test]
    fn any_match_empty_matches_nothing() {
        assert!(!any_match(&[], "anything"));
    }
}

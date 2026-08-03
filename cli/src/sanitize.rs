//! Path sanitization for `extract`: turns a catalog path (forward-slash
//! separated, e.g. `SD/tileset/jungle.wpe`) into a platform-native relative
//! path, refusing anything that could escape the output directory.

use std::path::{Component, Path, PathBuf};

/// Converts a catalog path into a safe relative [`PathBuf`] (native
/// separators, no leading root, no `..` components), or `None` if the path
/// contains anything that could make it escape the directory it's joined
/// against (`..` components, an absolute/rooted segment, a Windows drive
/// prefix, ...).
///
/// Catalog paths use `/` separators, but a stray `\` is treated as a
/// separator too rather than passed through as a literal character, since a
/// literal backslash in a real SC:R asset path is not a thing we expect and
/// treating it as one would be the more dangerous assumption.
pub fn sanitize_relative_path(path: &str) -> Option<PathBuf> {
    let normalized = path.replace('\\', "/");
    let mut out = PathBuf::new();
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        // A colon is never valid in an SC:R asset path but is how Windows
        // spells a drive letter (`C:`) or an NTFS alternate data stream
        // (`file.txt:evil`); reject it outright rather than relying on
        // `Path`'s platform-specific interpretation, which only treats `C:`
        // specially on Windows and would let it slip through on Unix.
        if segment.contains(':') {
            return None;
        }
        // Route each remaining segment through `Path`'s own component
        // parser so other platform-specific oddities (`..`, a bare root)
        // are rejected the same way the platform would interpret them, not
        // just by our own guess at what's dangerous.
        match Path::new(segment).components().next() {
            Some(Component::Normal(s)) if s == segment => out.push(segment),
            _ => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_relative_path() {
        let out = sanitize_relative_path("SD/tileset/jungle.wpe").unwrap();
        assert_eq!(out, Path::new("SD").join("tileset").join("jungle.wpe"));
    }

    #[test]
    fn rejects_parent_dir_component() {
        assert_eq!(sanitize_relative_path("../etc/passwd"), None);
        assert_eq!(sanitize_relative_path("SD/../../etc/passwd"), None);
        assert_eq!(sanitize_relative_path("SD/tileset/../../../evil"), None);
    }

    #[test]
    fn leading_root_is_treated_as_relative_not_rejected() {
        // A leading `/` just contributes an empty split segment, which is
        // skipped like any other empty segment — the result never carries
        // a root component, so it's still safe to join against an output
        // directory (there's nothing here that could escape it).
        let out = sanitize_relative_path("/etc/passwd").unwrap();
        assert_eq!(out, Path::new("etc").join("passwd"));
    }

    #[test]
    fn treats_backslash_as_separator_and_still_rejects_traversal() {
        assert_eq!(sanitize_relative_path(r"..\..\evil"), None);
        assert_eq!(
            sanitize_relative_path(r"SD\tileset\jungle.wpe").unwrap(),
            Path::new("SD").join("tileset").join("jungle.wpe")
        );
    }

    #[test]
    fn rejects_windows_drive_prefix() {
        assert_eq!(sanitize_relative_path("C:/Windows/System32"), None);
    }

    #[test]
    fn empty_or_dot_only_path_is_rejected() {
        assert_eq!(sanitize_relative_path(""), None);
        assert_eq!(sanitize_relative_path("."), None);
        assert_eq!(sanitize_relative_path("./"), None);
    }

    #[test]
    fn ignores_redundant_current_dir_and_slashes() {
        let out = sanitize_relative_path("./SD//tileset/./jungle.wpe").unwrap();
        assert_eq!(out, Path::new("SD").join("tileset").join("jungle.wpe"));
    }
}

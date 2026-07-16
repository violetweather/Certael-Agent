use anyhow::{bail, Result};

pub(crate) fn sanitize_environment_entries(
    mut values: Vec<(String, String)>,
    read: usize,
    write: usize,
) -> Result<Vec<(String, String)>> {
    values.retain(|(key, _)| {
        !key.eq_ignore_ascii_case("CERTAEL_AGENT_READ_HANDLE")
            && !key.eq_ignore_ascii_case("CERTAEL_AGENT_WRITE_HANDLE")
    });
    values.push(("CERTAEL_AGENT_READ_HANDLE".into(), read.to_string()));
    values.push(("CERTAEL_AGENT_WRITE_HANDLE".into(), write.to_string()));
    values.sort_by_key(|(key, _)| key.to_uppercase());

    let mut sanitized = Vec::with_capacity(values.len());
    for (key, value) in values {
        if key.is_empty() || key.contains('\0') || value.contains('\0') {
            bail!("process environment contains an invalid entry");
        }

        // Windows uses entries such as `=C:=C:\\directory` to carry each
        // drive's current directory into a child process. Some parent
        // processes also inject undocumented pseudo-entries such as
        // `=::=::\\`. Preserve only the documented drive-current-directory
        // shape and drop other leading-`=` bookkeeping entries. Ordinary
        // environment variable names containing `=` remain invalid.
        let drive_current_directory = is_drive_current_directory_key(&key);
        if key.starts_with('=') && !drive_current_directory {
            continue;
        }
        if !drive_current_directory && key.contains('=') {
            bail!("process environment contains an invalid entry");
        }
        sanitized.push((key, value));
    }
    Ok(sanitized)
}

fn is_drive_current_directory_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() == 3 && bytes[0] == b'=' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_drive_current_directories_and_replaces_agent_handles() {
        let entries = sanitize_environment_entries(
            vec![
                ("Path".into(), r"C:\Windows\System32".into()),
                ("=C:".into(), r"C:\Games\Certael".into()),
                ("certael_agent_read_handle".into(), "attacker".into()),
            ],
            123,
            456,
        )
        .expect("valid Windows environment entries should be accepted");

        assert!(entries.contains(&("=C:".into(), r"C:\Games\Certael".into())));
        assert!(entries.contains(&("CERTAEL_AGENT_READ_HANDLE".into(), "123".into())));
        assert!(entries.contains(&("CERTAEL_AGENT_WRITE_HANDLE".into(), "456".into())));
        assert!(!entries.iter().any(|(_, value)| value == "attacker"));
    }

    #[test]
    fn drops_unknown_windows_pseudo_environment_entries() {
        let entries = sanitize_environment_entries(
            vec![
                ("Path".into(), r"C:\Windows\System32".into()),
                ("=::".into(), r"::\".into()),
                ("=CC:".into(), "ignored".into()),
                ("=C:extra".into(), "ignored".into()),
                ("=1:".into(), "ignored".into()),
                ("=".into(), "ignored".into()),
            ],
            123,
            456,
        )
        .expect("unknown Windows pseudo-environment entries should be dropped");

        assert!(entries.contains(&("Path".into(), r"C:\Windows\System32".into())));
        assert!(!entries.iter().any(|(key, _)| key.starts_with('=')));
    }

    #[test]
    fn rejects_invalid_ordinary_environment_entries() {
        for key in ["", "INVALID=KEY", "INVALID\0KEY"] {
            assert!(
                sanitize_environment_entries(vec![(key.into(), "value".into())], 123, 456).is_err(),
                "unexpectedly accepted environment key {key:?}"
            );
        }
        assert!(sanitize_environment_entries(
            vec![("VALID".into(), "invalid\0value".into())],
            123,
            456
        )
        .is_err());
    }
}

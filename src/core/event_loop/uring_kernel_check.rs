//! Runtime kernel-version gate for the `io_uring` backend. Separate
//! from `uring_backend` itself so the version-parsing logic (the only
//! part of this that's meaningfully pure/testable -- the actual
//! `uname(2)` call obviously isn't) can be unit tested without needing
//! a real io_uring-capable kernel to run the test suite on.
//!
//! This exists as a *first*, earlier check than simply calling
//! `io_uring_setup()` and seeing if it fails -- so a too-old kernel
//! and a kernel that's new enough but has `kernel.io_uring_disabled`
//! set (or is otherwise blocked by a seccomp/container policy) produce
//! two different, specific error messages rather than one generic
//! "io_uring_setup failed: EPERM" that leaves the operator guessing
//! which of several possible causes applies.

/// The minimum kernel version this backend supports. Chosen as 5.10 --
/// the version the wider io_uring ecosystem (liburing's own docs
/// included) treats as the first genuinely stable baseline: the
/// fixed-buffer and splice operations this backend relies on for its
/// core accept/read/write/sendfile-equivalent paths either don't exist
/// or are unreliable on anything older (io_uring's initial 5.1 release
/// was incomplete and buggy; several operations this backend depends
/// on didn't stabilize until 5.6; 5.10 added IOSQE_BUFFER_SELECT and is
/// the version most commonly cited as safe to depend on in production).
/// Not 5.19 or 6.1 (where later features like multishot recv/send_zc
/// stabilized) -- those are optimizations this backend doesn't yet use,
/// not requirements for the operations it does.
pub const MIN_SUPPORTED_KERNEL: (u32, u32) = (5, 10);

/// Parses the `(major, minor)` version out of a `uname -r`-style
/// release string (e.g. `"5.15.0-91-generic"`, `"6.6.30+"`,
/// `"5.10.0"`). Anything after the first two dot-separated numeric
/// components (the patch level, any distro suffix) is ignored -- only
/// major.minor is meaningful for the comparison this exists to make.
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    // The minor component may be immediately followed by a non-numeric
    // suffix with no further '.' separator in some release strings
    // (uncommon, but "5.10-something" is possible in principle) --
    // take only the leading digits rather than requiring the whole
    // second segment to parse cleanly.
    let minor_segment = parts.next()?;
    let minor_digits: String = minor_segment.chars().take_while(|c| c.is_ascii_digit()).collect();
    let minor = minor_digits.parse::<u32>().ok()?;
    Some((major, minor))
}

/// Reads the running kernel's version via `uname(2)` and checks it
/// against `MIN_SUPPORTED_KERNEL`. Returns `Err` with an operator-facing
/// message (never a silent fallback -- see this module's own doc
/// comment) if the kernel is too old, or if the version genuinely
/// can't be determined at all.
pub fn check_kernel_version() -> Result<(), String> {
    let release = read_kernel_release()?;
    let (major, minor) = parse_kernel_version(&release)
        .ok_or_else(|| format!("could not parse kernel version from uname release string: '{release}'"))?;

    if (major, minor) < MIN_SUPPORTED_KERNEL {
        return Err(format!(
            "running kernel {release} is older than the minimum supported {}.{} for the io_uring backend \
            (this backend's core accept/read/write paths depend on operations that are missing or unreliable \
            on earlier kernels). Rebuild without `--features io_uring` to use the default mio/epoll backend \
            instead, which has no minimum kernel requirement beyond what mio itself needs.",
            MIN_SUPPORTED_KERNEL.0, MIN_SUPPORTED_KERNEL.1
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_kernel_release() -> Result<String, String> {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(format!("uname(2) failed: {}", std::io::Error::last_os_error()));
    }
    // utsname.release is a fixed-size, NUL-terminated char array (not
    // guaranteed to be valid UTF-8 in general, but a kernel release
    // string always is in practice) -- read up to the first NUL byte.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(uts.release.as_ptr() as *const u8, uts.release.len())
    };
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..nul_pos]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_version() {
        assert_eq!(parse_kernel_version("5.10.0"), Some((5, 10)));
    }

    #[test]
    fn parses_distro_suffixed_version() {
        assert_eq!(parse_kernel_version("5.15.0-91-generic"), Some((5, 15)));
        assert_eq!(parse_kernel_version("6.6.30+"), Some((6, 6)));
        assert_eq!(parse_kernel_version("6.1.0-18-cloud-amd64"), Some((6, 1)));
    }

    #[test]
    fn parses_minor_with_no_further_dot() {
        assert_eq!(parse_kernel_version("5.10-custom"), Some((5, 10)));
    }

    #[test]
    fn rejects_unparseable_input() {
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("not-a-version"), None);
        assert_eq!(parse_kernel_version("5"), None);
    }

    #[test]
    fn version_ordering_matches_expectations() {
        // Exercises the exact comparison check_kernel_version performs,
        // without needing to fake uname(2) itself.
        assert!((5, 9) < MIN_SUPPORTED_KERNEL);
        assert!((4, 18) < MIN_SUPPORTED_KERNEL);
        assert!((5, 10) >= MIN_SUPPORTED_KERNEL);
        assert!((5, 19) >= MIN_SUPPORTED_KERNEL);
        assert!((6, 1) >= MIN_SUPPORTED_KERNEL);
    }

    #[test]
    fn read_kernel_release_returns_a_parseable_string_on_this_host() {
        // This test only makes sense on Linux (where the whole io_uring
        // backend is buildable at all -- see lib.rs's compile_error!
        // guard), and only actually runs when the io_uring feature is
        // enabled, same as the rest of this module.
        let release = read_kernel_release().expect("uname(2) should succeed on any real Linux host");
        assert!(
            parse_kernel_version(&release).is_some(),
            "expected a parseable major.minor from a real uname release string, got: {release}"
        );
    }
}

//! Extended-access-control detection for the private-store boundary
//! (review remediation: owner-only mode bits are not sufficient on macOS,
//! where POSIX ACLs are not xattrs and an inherited or explicit ACL
//! survives `fchmod(0700)`).
//!
//! **This module holds the only `unsafe` in the crate.** The crate-wide
//! lint is `unsafe_code = "deny"` (relaxed from `"forbid"` precisely so
//! this one module can scope an allow; `forbid` cannot be scoped). The
//! `unsafe` surface is exactly two FFI calls on macOS:
//!
//! - `acl_get_fd(fd)` — fetch the access ACL of an open descriptor;
//! - `acl_free(ptr)` — release it.
//!
//! The pinned `libc` crate supplies the C types and `__error` (errno)
//! accessor. It does NOT wrap the ACL API itself (verified by grep against
//! the pinned source), so the two symbols are declared here against
//! libSystem, which is always linked. Both calls take and return raw
//! handles only; no pointers are dereferenced and no buffers are shared.
//!
//! Semantics, deliberately fail-closed and detect-only (nothing is ever
//! stripped):
//!
//! - macOS: `acl_get_fd` returning NULL with `errno == ENOENT` means no
//!   ACL — accept. NULL with any other errno means the state is unknown —
//!   reject. A non-NULL ACL means an access-control list exists beyond
//!   what the mode bits express — free it and reject.
//! - Linux: `system.posix_acl_access` absent — accept. Present — parse:
//!   header version must be 2, then exactly the three minimal entries
//!   `USER_OBJ`/`GROUP_OBJ`/`OTHER` with undefined ids (equivalent to the
//!   mode bits) — accept; anything else — reject. Truncation, a bad
//!   version, or an odd entry count all reject.
//! - Any other Unix: reject unconditionally — an unported platform cannot
//!   prove the absence of ACLs, so it fails closed.

#![allow(unsafe_code)]

use crate::Result;

/// Reject `file` when any access-control entries exist beyond what its
/// mode bits express. Unknown state fails closed.
pub(crate) fn reject_extended_acl(file: &std::fs::File) -> Result<()> {
    platform::reject_extended_acl(file)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::os::unix::io::AsRawFd;

    use crate::{LabError, Result};

    // The pinned libc wraps neither symbol; both are stable libSystem
    // exports since 10.4. `acl_t` is an opaque pointer.
    unsafe extern "C" {
        fn acl_get_fd(fd: libc::c_int) -> *mut libc::c_void;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    pub(super) fn reject_extended_acl(file: &std::fs::File) -> Result<()> {
        // SAFETY: `file` is a valid open descriptor for the duration of
        // the call. `acl_get_fd` either returns NULL (errno distinguishes
        // "no ACL" from real errors) or an owned ACL handle that is freed
        // exactly once before returning. No pointer is dereferenced.
        let acl = unsafe { acl_get_fd(file.as_raw_fd()) };
        if acl.is_null() {
            // SAFETY: `__error` returns the calling thread's errno slot.
            let errno = unsafe { *libc::__error() };
            return if errno == libc::ENOENT {
                Ok(())
            } else {
                Err(LabError::Storage)
            };
        }
        // SAFETY: `acl` is a non-NULL handle owned by this call site.
        unsafe { acl_free(acl) };
        Err(LabError::Storage)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use rustix::fs;

    use crate::{LabError, Result};

    const ACL_XATTR: &str = "system.posix_acl_access";

    pub(super) fn reject_extended_acl(file: &std::fs::File) -> Result<()> {
        let mut buffer = [0_u8; 512];
        match fs::fgetxattr(file, ACL_XATTR, &mut buffer) {
            Ok(size) => parse_linux_acl_xattr(&buffer[..size]),
            Err(rustix::io::Errno::NODATA) => Ok(()),
            Err(_) => Err(LabError::Storage),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use crate::{LabError, Result};

    pub(super) fn reject_extended_acl(_file: &std::fs::File) -> Result<()> {
        // Unported platform: the absence of ACLs cannot be proven, so the
        // boundary fails closed.
        Err(LabError::Storage)
    }
}

/// Parse a Linux `system.posix_acl_access` value: a `u32` version header
/// (must be 2) followed by `(tag u16, perm u16, id u32)` entries. Exactly
/// the three minimal entries — `USER_OBJ`, `GROUP_OBJ`, `OTHER`, in the
/// canonical order with undefined ids — are equivalent to the mode bits
/// and accepted; anything else is an extended ACL and rejected. All
/// malformed input rejects.
///
/// Note on constants: `ACL_OTHER` is `0x20` (the review brief wrote
/// `0x10`, which is `ACL_MASK`; the kernel's `posix_acl.h` values are
/// authoritative). Pure function, unit-tested on every platform.
#[cfg(any(test, target_os = "linux"))]
fn parse_linux_acl_xattr(bytes: &[u8]) -> Result<()> {
    use crate::LabError;
    const POSIX_ACL_XATTR_VERSION: u32 = 2;
    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_OTHER: u16 = 0x20;
    const ACL_UNDEFINED_ID: u32 = 0xFFFF_FFFF;
    const HEADER: usize = 4;
    const ENTRY: usize = 8;

    if bytes.len() < HEADER || (bytes.len() - HEADER) % ENTRY != 0 {
        return Err(LabError::Storage);
    }
    let version = u32::from_le_bytes(bytes[..HEADER].try_into().map_err(|_| LabError::Storage)?);
    if version != POSIX_ACL_XATTR_VERSION {
        return Err(LabError::Storage);
    }
    let entries = &bytes[HEADER..];
    if entries.len() != 3 * ENTRY {
        return Err(LabError::Storage);
    }
    for (index, expected_tag) in [ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_OTHER]
        .iter()
        .enumerate()
    {
        let entry = &entries[index * ENTRY..(index + 1) * ENTRY];
        let tag = u16::from_le_bytes(entry[0..2].try_into().map_err(|_| LabError::Storage)?);
        let id = u32::from_le_bytes(entry[4..8].try_into().map_err(|_| LabError::Storage)?);
        if tag != *expected_tag || id != ACL_UNDEFINED_ID {
            return Err(LabError::Storage);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_linux_acl_xattr;

    const HEADER: [u8; 4] = 2_u32.to_le_bytes();

    fn entry(tag: u16, perm: u16, id: u32) -> [u8; 8] {
        let mut out = [0_u8; 8];
        out[0..2].copy_from_slice(&tag.to_le_bytes());
        out[2..4].copy_from_slice(&perm.to_le_bytes());
        out[4..8].copy_from_slice(&id.to_le_bytes());
        out
    }

    fn minimal_acl() -> Vec<u8> {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(&entry(0x01, 0b111, 0xFFFF_FFFF));
        bytes.extend_from_slice(&entry(0x04, 0, 0xFFFF_FFFF));
        bytes.extend_from_slice(&entry(0x20, 0, 0xFFFF_FFFF));
        bytes
    }

    #[test]
    fn minimal_mode_equivalent_acl_is_accepted() {
        assert!(parse_linux_acl_xattr(&minimal_acl()).is_ok());
    }

    #[test]
    fn named_user_entry_is_rejected() {
        let mut bytes = HEADER.to_vec();
        bytes.extend_from_slice(&entry(0x01, 0b111, 0xFFFF_FFFF));
        bytes.extend_from_slice(&entry(0x02, 0b101, 1_000)); // ACL_USER
        bytes.extend_from_slice(&entry(0x04, 0, 0xFFFF_FFFF));
        bytes.extend_from_slice(&entry(0x10, 0b101, 0xFFFF_FFFF)); // ACL_MASK
        bytes.extend_from_slice(&entry(0x20, 0, 0xFFFF_FFFF));
        assert!(parse_linux_acl_xattr(&bytes).is_err());
    }

    #[test]
    fn malformed_acls_are_rejected() {
        // Bad version.
        let mut bad_version = minimal_acl();
        bad_version[0] = 3;
        assert!(parse_linux_acl_xattr(&bad_version).is_err());
        // Truncated header.
        assert!(parse_linux_acl_xattr(&[2, 0]).is_err());
        // Truncated entry (odd length).
        assert!(parse_linux_acl_xattr(&minimal_acl()[..27]).is_err());
        // Wrong entry count.
        assert!(parse_linux_acl_xattr(&minimal_acl()[..20]).is_err());
        // Wrong tag order.
        let mut wrong_order = HEADER.to_vec();
        wrong_order.extend_from_slice(&entry(0x04, 0, 0xFFFF_FFFF));
        wrong_order.extend_from_slice(&entry(0x01, 0b111, 0xFFFF_FFFF));
        wrong_order.extend_from_slice(&entry(0x20, 0, 0xFFFF_FFFF));
        assert!(parse_linux_acl_xattr(&wrong_order).is_err());
        // Defined id on an OBJ entry.
        let mut defined_id = minimal_acl();
        defined_id[8..12].copy_from_slice(&1_000_u32.to_le_bytes());
        assert!(parse_linux_acl_xattr(&defined_id).is_err());
    }
}

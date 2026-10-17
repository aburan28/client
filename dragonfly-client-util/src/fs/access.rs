/*
 *     Copyright 2025 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Access checks on behalf of the local callers of dfdaemon.
//!
//! dfdaemon usually runs with more privileges than the local processes
//! calling it over its unix socket, so it must not read or write a path for a
//! caller that the caller could not read or write itself. Otherwise any local
//! user able to reach the socket could make dfdaemon overwrite or disclose
//! files of other users, including system files when dfdaemon runs as root.

use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The identity of a local caller, from the credentials of its unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// The user id of the caller.
    pub uid: u32,

    /// The primary group id of the caller.
    pub gid: u32,
}

/// The read permission bit of a permission triplet.
const READ: u32 = 0o4;

/// The write permission bit of a permission triplet.
const WRITE: u32 = 0o2;

/// The execute (search) permission bit of a permission triplet.
const EXECUTE: u32 = 0o1;

/// Implements the caller.
impl Caller {
    /// Returns whether the caller bypasses the checks: root, or the user
    /// dfdaemon runs as, which can already access everything dfdaemon can.
    pub fn is_privileged(&self) -> bool {
        self.uid == 0 || self.uid == rustix::process::geteuid().as_raw()
    }

    /// Returns whether the caller has all the `wanted` permission bits on the
    /// file with the metadata, following the owner, group, other precedence
    /// of the permission bits. Only the primary group of the caller is known,
    /// so an access granted through a supplementary group is refused.
    fn has_permissions(&self, metadata: &Metadata, wanted: u32) -> bool {
        let mode = metadata.mode();
        let granted = if metadata.uid() == self.uid {
            (mode >> 6) & 0o7
        } else if metadata.gid() == self.gid {
            (mode >> 3) & 0o7
        } else {
            mode & 0o7
        };

        granted & wanted == wanted
    }

    /// Checks that the caller could write the file at `path` itself: an
    /// existing file must be writable by the caller, and a new file must be
    /// in a directory the caller can write and search. The final component
    /// is resolved like the open of dfdaemon resolves it, so a symbolic link
    /// is checked against its target.
    pub fn check_writable(&self, path: &Path) -> io::Result<()> {
        if self.is_privileged() {
            return Ok(());
        }

        match std::fs::metadata(path) {
            Ok(metadata) => {
                if self.has_permissions(&metadata, WRITE) {
                    return Ok(());
                }

                Err(permission_denied(path, "is not writable by the caller"))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let parent = parent_dir(path);
                let metadata = std::fs::metadata(parent)?;
                if metadata.is_dir() && self.has_permissions(&metadata, WRITE | EXECUTE) {
                    return Ok(());
                }

                Err(permission_denied(
                    parent,
                    "is not a directory writable by the caller",
                ))
            }
            Err(err) => Err(err),
        }
    }

    /// Checks that the caller could read the file at `path` itself.
    pub fn check_readable(&self, path: &Path) -> io::Result<()> {
        if self.is_privileged() {
            return Ok(());
        }

        let metadata = std::fs::metadata(path)?;
        if self.has_permissions(&metadata, READ) {
            return Ok(());
        }

        Err(permission_denied(path, "is not readable by the caller"))
    }
}

/// Returns the directory containing the path, the current directory for a
/// bare file name.
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Returns the permission denied error for the path.
fn permission_denied(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} {}", path.display(), reason),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    /// A caller that is neither root nor the user of the test process, and
    /// not in the group of the test files.
    fn other() -> Caller {
        Caller {
            uid: 65_000,
            gid: 65_000,
        }
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn privileged_callers_bypass_the_checks() {
        let root = Caller { uid: 0, gid: 0 };
        assert!(root.is_privileged());
        assert!(root.check_writable(Path::new("/nonexistent/x")).is_ok());

        let euid = rustix::process::geteuid().as_raw();
        let same = Caller { uid: euid, gid: 1 };
        assert!(same.is_privileged());
        assert!(!other().is_privileged());
    }

    #[test]
    fn writes_follow_the_permission_bits() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();

        // Writable by others only when the other bits allow it.
        chmod(&file, 0o644);
        assert!(other().check_writable(&file).is_err());
        chmod(&file, 0o646);
        assert!(other().check_writable(&file).is_ok());

        // A new file needs a writable and searchable directory.
        let new = dir.path().join("new");
        chmod(dir.path(), 0o755);
        assert!(other().check_writable(&new).is_err());
        chmod(dir.path(), 0o757);
        assert!(other().check_writable(&new).is_ok());
        chmod(dir.path(), 0o756);
        assert!(other().check_writable(&new).is_err());

        // A missing directory is an error.
        assert!(other()
            .check_writable(&dir.path().join("missing").join("x"))
            .is_err());
        chmod(dir.path(), 0o755);
    }

    #[test]
    fn symlinks_are_checked_against_their_target() {
        let dir = tempdir().unwrap();
        chmod(dir.path(), 0o777);
        let target = dir.path().join("target");
        std::fs::write(&target, b"secret").unwrap();
        chmod(&target, 0o600);

        // A link in a directory writable by the caller does not grant access
        // to a target the caller cannot access.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(other().check_writable(&link).is_err());
        assert!(other().check_readable(&link).is_err());
        chmod(dir.path(), 0o755);
    }

    #[test]
    fn owner_and_group_bits_take_precedence() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();

        // The owner bits apply to the owner even when the other bits grant
        // more.
        chmod(&file, 0o066);
        let owner = Caller {
            uid: metadata.uid(),
            gid: 65_000,
        };
        assert!(!owner.has_permissions(&std::fs::metadata(&file).unwrap(), READ));

        // The group bits apply to the group.
        chmod(&file, 0o640);
        let member = Caller {
            uid: 65_000,
            gid: metadata.gid(),
        };
        assert!(member.has_permissions(&std::fs::metadata(&file).unwrap(), READ));
        assert!(!member.has_permissions(&std::fs::metadata(&file).unwrap(), WRITE));
        assert!(other().check_readable(&file).is_err());
    }
}

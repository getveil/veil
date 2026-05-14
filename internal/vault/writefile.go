package vault

import (
	"io"
	"os"
	"syscall"
)

// WriteFileNoFollow writes data to path at mode. Unlike os.WriteFile it
// closes two holes called out in the H1/H9 audit findings:
//
//   - Leaf-symlink refusal. open(2) is called with O_NOFOLLOW, so a pre-
//     planted symlink at path fails the call with ELOOP rather than dumping
//     data through to the link's target.
//   - Mode enforcement on pre-existing files. os.WriteFile / OpenFile only
//     apply mode on creation; a pre-existing file with widened perms would
//     otherwise keep them. fchmod via the just-opened fd tightens perms
//     before any bytes are written, with no path-based TOCTOU window.
//
// O_TRUNC fires at open, so the file is empty when fchmod runs — there is
// no instant at which our bytes are readable under the pre-existing wider
// mode.
func WriteFileNoFollow(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- O_NOFOLLOW refuses any leaf-symlink injection at this
	// exact point; callers pass derived paths.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if cerr := f.Chmod(mode); cerr != nil {
		_ = f.Close()
		return cerr
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	return f.Close()
}

// ReadFileNoFollow is the read counterpart to WriteFileNoFollow: open(2) is
// called with O_NOFOLLOW so a pre-planted symlink at path fails with ELOOP
// rather than pulling the link target's bytes into our processing pipeline.
// Used for files whose contents drive downstream filesystem operations
// (e.g. vault.meta, whose vaulted-files registry steers uninstall paths).
func ReadFileNoFollow(path string) ([]byte, error) {
	// #nosec G304 -- O_NOFOLLOW refuses leaf-symlink injection; callers pass
	// derived paths.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

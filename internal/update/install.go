package update

import (
	"errors"
	"io/fs"
	"os"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// Install puts a verified new executable in place of exe. Windows won't overwrite a
// running program but will let it be renamed, so the current one moves aside and the
// new one takes its name. The old copy goes at the next start, by Cleanup.
//
// The returned function undoes this, for when the new program won't start.
func Install(exe string, data []byte) (rollback func() error, err error) {
	newPath, oldPath := exe+".new", exe+".old"
	if err := writeSynced(newPath, data); err != nil {
		os.Remove(newPath)
		return nil, describeWrite(err)
	}
	// A leftover from an earlier update. If it's somehow still locked, the rename
	// below reports that.
	os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return nil, describeWrite(err)
	}
	if err := os.Rename(newPath, exe); err != nil {
		// Whatever happens, the app must still be there next time.
		if restoreErr := os.Rename(oldPath, exe); restoreErr != nil {
			return nil, errors.Join(describeWrite(err), restoreErr)
		}
		os.Remove(newPath)
		return nil, describeWrite(err)
	}
	return func() error {
		if err := os.Remove(exe); err != nil {
			return err
		}
		return os.Rename(oldPath, exe)
	}, nil
}

// Cleanup removes what an earlier update left. Failing is harmless: it's retried at
// the next start and overwritten by the next update.
func Cleanup(exe string) {
	os.Remove(exe + ".old")
	os.Remove(exe + ".new")
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// describeWrite explains the usual cause: the app sits somewhere its user can't
// write, such as Program Files.
func describeWrite(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return verdict.Err("err.update.noWrite")
	}
	return verdict.Err("err.update.install", "detail", err.Error())
}

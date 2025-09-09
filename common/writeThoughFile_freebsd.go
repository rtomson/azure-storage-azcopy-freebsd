//go:build freebsd

// Copyright © 2017 Microsoft <wastore@microsoft.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package common

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// 100-nanosecond intervals from Windows Epoch (January 1, 1601) to Unix Epoch (January 1, 1970).
const (
	TICKS_FROM_WINDOWS_EPOCH_TO_UNIX_EPOCH = 116444736000000000
)

// windows.Filetime.
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// windows.ByHandleFileInformation
type ByHandleFileInformation struct {
	FileAttributes     uint32
	CreationTime       Filetime
	LastAccessTime     Filetime
	LastWriteTime      Filetime
	VolumeSerialNumber uint32
	FileSizeHigh       uint32
	FileSizeLow        uint32
	NumberOfLinks      uint32
	FileIndexHigh      uint32
	FileIndexLow       uint32
}

// Nanoseconds converts Filetime (as ticks since Windows Epoch) to nanoseconds since Unix Epoch (January 1, 1970).
func (ft *Filetime) Nanoseconds() int64 {
	// 100-nanosecond intervals (ticks) since Windows Epoch (January 1, 1601).
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)

	// 100-nanosecond intervals since Unix Epoch (January 1, 1970).
	nsec -= TICKS_FROM_WINDOWS_EPOCH_TO_UNIX_EPOCH

	// nanoseconds since Unix Epoch.
	return nsec * 100
}

// Convert nanoseconds since Unix Epoch (January 1, 1970) to Filetime since Windows Epoch (January 1, 1601).
func NsecToFiletime(nsec int64) Filetime {
	// 100-nanosecond intervals since Unix Epoch (January 1, 1970).
	nsec /= 100

	// 100-nanosecond intervals since Windows Epoch (January 1, 1601).
	nsec += TICKS_FROM_WINDOWS_EPOCH_TO_UNIX_EPOCH

	return Filetime{LowDateTime: uint32(nsec & 0xFFFFFFFF), HighDateTime: uint32(nsec >> 32)}
}

// WindowsTicksToUnixNano converts ticks (100-ns intervals) since Windows Epoch to nanoseconds since Unix Epoch.
func WindowsTicksToUnixNano(ticks int64) int64 {
	// 100-nanosecond intervals since Unix Epoch (January 1, 1970).
	ticks -= TICKS_FROM_WINDOWS_EPOCH_TO_UNIX_EPOCH

	// nanoseconds since Unix Epoch (January 1, 1970).
	return ticks * 100
}

// UnixNanoToWindowsTicks converts nanoseconds since Unix Epoch to ticks since Windows Epoch.
func UnixNanoToWindowsTicks(nsec int64) int64 {
	// 100-nanosecond intervals since Unix Epoch (January 1, 1970).
	nsec /= 100

	// 100-nanosecond intervals since Windows Epoch (January 1, 1601).
	nsec += TICKS_FROM_WINDOWS_EPOCH_TO_UNIX_EPOCH

	return nsec
}

// TimespecToFiletime converts a unix.Timespec to Filetime.
// Note that Timespec is from Unix Epoch while Filetime holds time from Windows Epoch.
func TimespecToFiletime(ts unix.Timespec) Filetime {
	return NsecToFiletime(int64(ts.Sec)*1_000_000_000 + int64(ts.Nsec))
}

func GetFileInformation(path string, isNFSCopy bool) (ByHandleFileInformation, error) {
	var st unix.Stat_t

	// Use regular stat syscall on FreeBSD (follows symlinks)
	err := unix.Stat(path, &st)
	if err != nil {
		return ByHandleFileInformation{}, fmt.Errorf("stat(%s) failed: %v", path, err)
	}

	var info ByHandleFileInformation

	// Map minimal file attributes for FreeBSD
	// Set directory flag if it's a directory (0x10 = FILE_ATTRIBUTE_DIRECTORY)
	if (st.Mode & syscall.S_IFMT) == syscall.S_IFDIR {
		info.FileAttributes |= 0x10
	} else {
		info.FileAttributes = 0x80 // FILE_ATTRIBUTE_NORMAL
	}

	// FreeBSD: Use available time fields (no birthtime in unix.Stat_t)
	// Use modification time as creation time since birthtime is not available
	info.CreationTime = TimespecToFiletime(unix.Timespec{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec})
	info.LastAccessTime = TimespecToFiletime(unix.Timespec{Sec: st.Atim.Sec, Nsec: st.Atim.Nsec})
	info.LastWriteTime = TimespecToFiletime(unix.Timespec{Sec: st.Mtim.Sec, Nsec: st.Mtim.Nsec})

	// Volume serial number not applicable on FreeBSD
	info.VolumeSerialNumber = 0

	size := uint64(st.Size)
	info.FileSizeHigh = uint32(size >> 32)
	info.FileSizeLow = uint32(size & 0xFFFFFFFF)

	info.NumberOfLinks = uint32(st.Nlink)

	ino := uint64(st.Ino)
	info.FileIndexHigh = uint32(ino >> 32)
	info.FileIndexLow = uint32(ino & 0xFFFFFFFF)

	return info, nil
}

func CreateFileOfSizeWithWriteThroughOption(destinationPath string, fileSize int64, writeThrough bool, t FolderCreationTracker, forceIfReadOnly bool) (*os.File, error) {
	// forceIfReadOnly is not used on this OS

	err := CreateParentDirectoryIfNotExist(destinationPath, t)
	if err != nil {
		return nil, err
	}

	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if writeThrough {
		flags = flags | os.O_SYNC // technically, O_DSYNC may be very slightly faster, but its not exposed in the os package
	}
	f, err := os.OpenFile(destinationPath, flags, DEFAULT_FILE_PERM)
	if err != nil {
		return nil, err
	}

	if fileSize == 0 {
		return f, err
	}

	// FreeBSD: fallocate not universally available; use Truncate
	if err := f.Truncate(fileSize); err != nil {
		_ = f.Close()
		return nil, err
	}

	return f, nil
}

func SetBackupMode(enable bool, fromTo FromTo) error {
	// n/a on this platform
	return nil
}

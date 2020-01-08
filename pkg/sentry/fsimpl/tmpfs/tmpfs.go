// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package tmpfs provides a filesystem implementation that behaves like tmpfs:
// the Dentry tree is the sole source of truth for the state of the filesystem.
//
// Lock order:
//
// filesystem.mu
//   regularFileFD.offMu
//     regularFile.mu
//   inode.mu
package tmpfs

import (
	"fmt"
	"math"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// memFile is used to allocate pages to for regular files.
	memFile *pgalloc.MemoryFile

	// mu serializes changes to the Dentry tree.
	mu sync.RWMutex

	nextInoMinusOne uint64 // accessed using atomic memory operations
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	memFileProvider := pgalloc.MemoryFileProviderFromContext(ctx)
	if memFileProvider == nil {
		panic("MemoryFileProviderFromContext returned nil")
	}
	fs := filesystem{
		memFile: memFileProvider.MemoryFile(),
	}
	fs.vfsfs.Init(vfsObj, &fs)
	root := fs.newDentry(fs.newDirectory(creds, 01777))
	return &fs.vfsfs, &root.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	// inode is the inode represented by this dentry. Multiple Dentries may
	// share a single non-directory inode (with hard links). inode is
	// immutable.
	inode *inode

	// tmpfs doesn't count references on dentries; because the dentry tree is
	// the sole source of truth, it is by definition always consistent with the
	// state of the filesystem. However, it does count references on inodes,
	// because inode resources are released when all references are dropped.
	// (tmpfs doesn't really have resources to release, but we implement
	// reference counting because tmpfs regular files will.)

	// dentryEntry (ugh) links dentries into their parent directory.childList.
	dentryEntry
}

func (fs *filesystem) newDentry(inode *inode) *dentry {
	d := &dentry{
		inode: inode,
	}
	d.vfsd.Init(d)
	return d
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	d.inode.incRef()
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	return d.inode.tryIncRef()
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	d.inode.decRef()
}

// inode represents a filesystem object.
type inode struct {
	// refs is a reference count. refs is accessed using atomic memory
	// operations.
	//
	// A reference is held on all inodes that are reachable in the filesystem
	// tree. For non-directories (which may have multiple hard links), this
	// means that a reference is dropped when nlink reaches 0. For directories,
	// nlink never reaches 0 due to the "." entry; instead,
	// filesystem.RmdirAt() drops the reference.
	refs int64

	// Inode metadata; protected by mu and accessed using atomic memory
	// operations unless otherwise specified.
	mu    sync.RWMutex
	mode  uint32 // excluding file type bits, which are based on impl
	nlink uint32 // protected by filesystem.mu instead of inode.mu
	uid   uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid   uint32 // auth.KGID, but ...
	ino   uint64 // immutable

	impl interface{} // immutable
}

const maxLinks = math.MaxUint32

func (i *inode) init(impl interface{}, fs *filesystem, creds *auth.Credentials, mode linux.FileMode) {
	i.refs = 1
	i.mode = uint32(mode)
	i.uid = uint32(creds.EffectiveKUID)
	i.gid = uint32(creds.EffectiveKGID)
	i.ino = atomic.AddUint64(&fs.nextInoMinusOne, 1)
	// i.nlink initialized by caller
	i.impl = impl
}

// incLinksLocked increments i's link count.
//
// Preconditions: filesystem.mu must be locked for writing. i.nlink != 0.
// i.nlink < maxLinks.
func (i *inode) incLinksLocked() {
	if i.nlink == 0 {
		panic("tmpfs.inode.incLinksLocked() called with no existing links")
	}
	if i.nlink == maxLinks {
		panic("memfs.inode.incLinksLocked() called with maximum link count")
	}
	atomic.AddUint32(&i.nlink, 1)
}

// decLinksLocked decrements i's link count.
//
// Preconditions: filesystem.mu must be locked for writing. i.nlink != 0.
func (i *inode) decLinksLocked() {
	if i.nlink == 0 {
		panic("tmpfs.inode.decLinksLocked() called with no existing links")
	}
	atomic.AddUint32(&i.nlink, ^uint32(0))
}

func (i *inode) incRef() {
	if atomic.AddInt64(&i.refs, 1) <= 1 {
		panic("tmpfs.inode.incRef() called without holding a reference")
	}
}

func (i *inode) tryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&i.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&i.refs, refs, refs+1) {
			return true
		}
	}
}

func (i *inode) decRef() {
	if refs := atomic.AddInt64(&i.refs, -1); refs == 0 {
		// This is unnecessary; it's mostly to simulate what tmpfs would do.
		if regFile, ok := i.impl.(*regularFile); ok {
			regFile.mu.Lock()
			regFile.data.DropAll(regFile.memFile)
			atomic.StoreUint64(&regFile.size, 0)
			regFile.mu.Unlock()
		}
	} else if refs < 0 {
		panic("tmpfs.inode.decRef() called without holding a reference")
	}
}

func (i *inode) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes, isDir bool) error {
	return vfs.GenericCheckPermissions(creds, ats, isDir, uint16(atomic.LoadUint32(&i.mode)), auth.KUID(atomic.LoadUint32(&i.uid)), auth.KGID(atomic.LoadUint32(&i.gid)))
}

// Go won't inline this function, and returning linux.Statx (which is quite
// big) means spending a lot of time in runtime.duffcopy(), so instead it's an
// output parameter.
func (i *inode) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
	stat.Blksize = 1 // usermem.PageSize in tmpfs
	stat.Nlink = atomic.LoadUint32(&i.nlink)
	stat.UID = atomic.LoadUint32(&i.uid)
	stat.GID = atomic.LoadUint32(&i.gid)
	stat.Mode = uint16(atomic.LoadUint32(&i.mode))
	stat.Ino = i.ino
	// TODO: device number
	switch impl := i.impl.(type) {
	case *regularFile:
		stat.Mode |= linux.S_IFREG
		stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
		stat.Size = uint64(atomic.LoadUint64(&impl.size))
		// In tmpfs, this will be FileRangeSet.Span() / 512 (but also cached in
		// a uint64 accessed using atomic memory operations to avoid taking
		// locks).
		stat.Blocks = allocatedBlocksForSize(stat.Size)
	case *directory:
		stat.Mode |= linux.S_IFDIR
	case *symlink:
		stat.Mode |= linux.S_IFLNK
		stat.Mask |= linux.STATX_SIZE | linux.STATX_BLOCKS
		stat.Size = uint64(len(impl.target))
		stat.Blocks = allocatedBlocksForSize(stat.Size)
	case *namedPipe:
		stat.Mode |= linux.S_IFIFO
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

// allocatedBlocksForSize returns the number of 512B blocks needed to
// accommodate the given size in bytes, as appropriate for struct
// stat::st_blocks and struct statx::stx_blocks. (Note that this 512B block
// size is independent of the "preferred block size for I/O", struct
// stat::st_blksize and struct statx::stx_blksize.)
func allocatedBlocksForSize(size uint64) uint64 {
	return (size + 511) / 512
}

func (i *inode) direntType() uint8 {
	switch i.impl.(type) {
	case *regularFile:
		return linux.DT_REG
	case *directory:
		return linux.DT_DIR
	case *symlink:
		return linux.DT_LNK
	default:
		panic(fmt.Sprintf("unknown inode type: %T", i.impl))
	}
}

// fileDescription is embedded by tmpfs implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) inode() *inode {
	return fd.vfsfd.Dentry().Impl().(*dentry).inode
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.inode().statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	// TODO: implement inode.setStat
	return syserror.EPERM
}

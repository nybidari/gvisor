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

package proc

import (
	"bytes"
	"sort"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

const defaultPermission = 0444

// InoGenerator generates unique inode numbers for a given filesystem.
type InoGenerator interface {
	NextIno() uint64
}

// tasksInode represents the inode for /proc/ directory.
//
// +stateify savable
type tasksInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeAttrs
	kernfs.OrderedChildren

	inoGen InoGenerator
	pidns  *kernel.PIDNamespace
}

var _ kernfs.Inode = (*tasksInode)(nil)

func newTasksInode(inoGen InoGenerator, k *kernel.Kernel, pidns *kernel.PIDNamespace) (*tasksInode, *kernfs.Dentry) {
	root := auth.NewRootCredentials(pidns.UserNamespace())
	contents := map[string]*kernfs.Dentry{
		"cpuinfo":     kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &vfs.StaticData{Data: cpuInfoData(k)}),
		"filesystems": kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &filesystemsData{}),
		"loadavg":     kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &loadavgData{}),
		"sys": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
			"kernel": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
				"hostname": kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &hostnameData{}),
				"shmall":   kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, shmData(linux.SHMALL)),
				"shmmax":   kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, shmData(linux.SHMMAX)),
				"shmmni":   kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, shmData(linux.SHMMNI)),
			}),
			"vm": kernfs.NewStaticDir(root, inoGen.NextIno(), 0555, map[string]*kernfs.Dentry{
				"mmap_min_addr":     kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &mmapMinAddrData{}),
				"overcommit_memory": kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &vfs.StaticData{Data: "0\n"}),
			}),
			"net": newNetDir(root, inoGen),
		}),
		"meminfo":     kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &meminfoData{}),
		"mounts":      kernfs.NewDynamicSymlink(root, inoGen.NextIno(), &vfs.StaticData{Data: "self/mounts"}),
		"self":        kernfs.NewDynamicSymlink(root, inoGen.NextIno(), &selfData{pidns: pidns}),
		"stat":        kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &statData{}),
		"thread-self": kernfs.NewDynamicSymlink(root, inoGen.NextIno(), &theadSelfData{pidns: pidns}),
		"uptime":      kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &uptimeData{}),
		"version":     kernfs.NewDynamicBytesFile(root, inoGen.NextIno(), defaultPermission, &versionData{}),
	}

	inode := &tasksInode{
		pidns:  pidns,
		inoGen: inoGen,
	}
	inode.InodeAttrs.Init(root, inoGen.NextIno(), linux.ModeDirectory|0555)

	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(dentry, contents)
	inode.IncLinks(links)

	return inode, dentry
}

// Lookup implements kernfs.inodeDynamicLookup.
func (i *tasksInode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	// Try to lookup a corresponding task.
	tid, err := strconv.ParseUint(name, 10, 64)
	if err != nil {
		return nil, syserror.ENOENT
	}

	task := i.pidns.TaskWithID(kernel.ThreadID(tid))
	if task == nil {
		return nil, syserror.ENOENT
	}

	_, taskDentry := newTaskInode(i.inoGen, task, i.pidns, true)
	return taskDentry.VFSDentry(), nil
}

// Valid implements kernfs.inodeDynamicLookup.
func (i *tasksInode) Valid(ctx context.Context) bool {
	return true
}

// IterDirents implements kernfs.inodeDynamicLookup.
func (i *tasksInode) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	var tids []int

	// Collect all tasks. Per linux we only include it in directory listings if
	// it's the leader. But for whatever crazy reason, you can still walk to the
	// given node.
	for _, tg := range i.pidns.ThreadGroups() {
		if leader := tg.Leader(); leader != nil {
			tids = append(tids, int(i.pidns.IDOfThreadGroup(tg)))
		}
	}

	if len(tids) == 0 {
		return offset, nil
	}

	sort.Ints(tids)
	tids = tids[relOffset:]
	for _, tid := range tids {
		dirent := vfs.Dirent{
			Name:    strconv.FormatUint(uint64(tid), 10),
			Type:    linux.DT_DIR,
			Ino:     i.inoGen.NextIno(),
			NextOff: offset + 1,
		}
		if !cb.Handle(dirent) {
			return offset, nil
		}
		offset++
	}
	return offset, nil
}

// Open implements kernfs.Inode.
func (i *tasksInode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &i.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

func (i *tasksInode) Stat(vsfs *vfs.Filesystem) linux.Statx {
	stat := i.InodeAttrs.Stat(vsfs)

	// Add dynamic children to link count.
	for _, tg := range i.pidns.ThreadGroups() {
		if leader := tg.Leader(); leader != nil {
			stat.Nlink++
		}
	}

	return stat
}

func cpuInfoData(k *kernel.Kernel) string {
	features := k.FeatureSet()
	if features == nil {
		// Kernel is always initialized with a FeatureSet.
		panic("cpuinfo read with nil FeatureSet")
	}
	var buf bytes.Buffer
	for i, max := uint(0), k.ApplicationCores(); i < max; i++ {
		features.CPUInfo(i, &buf)
	}
	return buf.String()
}

func shmData(v uint64) vfs.DynamicBytesSource {
	return &vfs.StaticData{Data: strconv.FormatUint(v, 10)}
}

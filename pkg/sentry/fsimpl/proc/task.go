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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// taskInode represents the inode for /proc/PID/ directory.
//
// +stateify savable
type taskInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNoDynamicLookup
	kernfs.InodeAttrs
	kernfs.OrderedChildren

	task *kernel.Task
}

var _ kernfs.Inode = (*taskInode)(nil)

func newTaskInode(inoGen InoGenerator, task *kernel.Task, pidns *kernel.PIDNamespace, isThreadGroup bool) (*taskInode, *kernfs.Dentry) {
	creds := task.Credentials()
	contents := map[string]*kernfs.Dentry{
		//"auxv":      newAuxvec(t, msrc),
		//"cmdline":   newExecArgInode(t, msrc, cmdlineExecArg),
		//"comm":      newComm(t, msrc),
		//"environ":   newExecArgInode(t, msrc, environExecArg),
		//"exe":       newExe(t, msrc),
		//"fd":        newFdDir(t, msrc),
		//"fdinfo":    newFdInfoDir(t, msrc),
		//"gid_map":   newGIDMap(t, msrc),
		"io":   kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, newIO(task, isThreadGroup)),
		"maps": kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, &mapsData{mapsCommon{t: task}}),
		//"mountinfo": seqfile.NewSeqFileInode(t, &mountInfoFile{t: t}, msrc),
		//"mounts":    seqfile.NewSeqFileInode(t, &mountsFile{t: t}, msrc),
		//"ns":        newNamespaceDir(t, msrc),
		"smaps":  kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, &smapsData{mapsCommon{t: task}}),
		"stat":   kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, &taskStatData{t: task, pidns: pidns, tgstats: isThreadGroup}),
		"statm":  kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, &statmData{t: task}),
		"status": kernfs.NewDynamicBytesFile(creds, inoGen.NextIno(), defaultPermission, &statusData{t: task, pidns: pidns}),
		//"uid_map":   newUIDMap(t, msrc),
	}
	if isThreadGroup {
		//contents["task"] = p.newSubtasks(t, msrc)
	}
	//if len(p.cgroupControllers) > 0 {
	//	contents["cgroup"] = newCGroupInode(t, msrc, p.cgroupControllers)
	//}

	inode := &taskInode{task: task}
	inode.InodeAttrs.Init(creds, inoGen.NextIno(), linux.ModeDirectory|0555)

	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	inode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := inode.OrderedChildren.Populate(dentry, contents)
	inode.IncLinks(links)

	return inode, dentry
}

// Valid implements kernfs.inodeDynamicLookup. This inode remains valid as long
// as the task is still running. When it's dead, another tasks with the same
// PID could replace it.
func (i *taskInode) Valid(ctx context.Context) bool {
	return i.task.ExitState() != kernel.TaskExitDead
}

// Open implements kernfs.Inode.
func (i *taskInode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &i.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

func newIO(t *kernel.Task, isThreadGroup bool) *ioData {
	if isThreadGroup {
		return &ioData{t.ThreadGroup()}
	}
	return &ioData{t}
}

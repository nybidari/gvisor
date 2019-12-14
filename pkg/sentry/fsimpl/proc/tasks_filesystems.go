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
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// filesystemsData backs /proc/filesystems.
//
// +stateify savable
type filesystemsData struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (*filesystemsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	for _, sys := range fs.GetFilesystems() {
		if !sys.AllowUserList() {
			continue
		}
		nodev := "nodev"
		if sys.Flags()&fs.FilesystemRequiresDev != 0 {
			nodev = ""
		}
		// Matches the format of fs/filesystems.c:filesystems_proc_show.
		fmt.Fprintf(buf, "%s\t%s\n", nodev, sys.Name())
	}
	return nil
}

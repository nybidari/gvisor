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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// uptimeData implements vfs.DynamicBytesSource for /proc/uptime.
//
// +stateify savable
type uptimeData struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (*uptimeData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	now := time.NowFromContext(ctx)

	// Pretend that we've spent zero time sleeping (second number).
	fmt.Fprintf(buf, "%.2f 0.00\n", now.Sub(k.Timekeeper().BootTime()).Seconds())
	return nil
}

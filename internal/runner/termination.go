//go:build darwin

package runner

import "time"

// childTerminationGrace is the time allowed between SIGTERM and SIGKILL when
// escalating child-process shutdown across platforms. Platform-specific code
// may use it where it has control over the escalation path; the Linux
// Pdeathsig mechanism delivers an immediate SIGTERM from the kernel and
// cannot be delayed, so this constant only applies to the user-level
// escalation path.
const childTerminationGrace = 3 * time.Second

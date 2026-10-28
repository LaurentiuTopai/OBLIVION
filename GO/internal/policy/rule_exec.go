package policy

import (
	"fmt"
	"strings"
	"time"

	"oblivion/internal/alert"
	"oblivion/internal/events"
)

// ExecFromTmp: semnatura (fara stare), MITRE T1059 / T1036.
type ExecFromTmp struct{}

var riskyPrefixes = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}

func (ExecFromTmp) ID() string { return "exec-from-tmp" }

func (ExecFromTmp) Match(ev *events.Event, st *State) *alert.Alert {
	if ev.Type != events.EvExec {
		return nil
	}
	for _, p := range riskyPrefixes {
		if strings.HasPrefix(ev.Path, p) {
			return &alert.Alert{
				Rule:     "exec-from-tmp",
				Severity: 3,
				Mitre:    "T1059",
				Tgid:     ev.Tgid,
				Ppid:     ev.Ppid,
				Comm:     ev.Comm,
				Exe:      ev.Path,
				Detail:   fmt.Sprintf("execuție din director riscant: %s", ev.Path),
				Time:     time.Now(),
			}
		}
	}
	return nil
}

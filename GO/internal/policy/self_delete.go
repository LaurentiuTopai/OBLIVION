package policy

import (
	"fmt"
	"time"

	"oblivion/internal/alert"
	"oblivion/internal/events"
)

type SelfDelete struct{}

func (SelfDelete) ID() string { return "binary-self-deletion" }

func (SelfDelete) Match(ev *events.Event, st *State) *alert.Alert {
	if ev.Type != events.EvInodeUnlink {
		return nil
	}

	p := st.Procs[ProcKey{ev.Tgid, ev.StartTime}]
	if p == nil || p.ExePath == "" {
		return nil
	}

	if ev.Path == p.ExePath {
		return &alert.Alert{
			Rule:     "binary-self-deletion",
			Severity: 4,
			Mitre:    "T1070.004",
			Tgid:     ev.Tgid,
			Ppid:     ev.Ppid,
			Comm:     ev.Comm,
			Exe:      p.ExePath,
			Detail:   fmt.Sprintf("process %s deleted its own binary: %s", p.Comm, ev.Path),
			Time:     time.Now(),
		}
	}
	return nil
}

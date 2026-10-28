package policy

import (
	"fmt"
	"oblivion/internal/alert"
	"oblivion/internal/events"
	"path/filepath"
	"strings"
	"time"
)

type Ransomware struct {
	RenameThreshold int
	UnlinkThreshold int
	CreateThreshold int
	ExtThreshold    int
	DirThreshold    int
	Window          time.Duration
	ScoreWindow     time.Duration
	AlertScore      int
}
var noteKeywords = []string{"readme", "decrypt", "recover", "restore", "how_to", "ransom"}

func slide(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}

func (Ransomware) ID() string { return "ransomeware-suspected" }

/*
	func returnAlert(){
		return &alert.Alert{
			Rule:	"RansomeWare",
			Severity:	5,
			Mitre: "",
			Tgid: ev.Tgid,
			Ppid:	ev.Ppid,
			Comm:	ev.Comm,
			Exe:	ev.Path,
			Detail:	fmt.Printf("Ransomeware detectat")

			Time:	time.Now(),
		}
	}
*/
func (r Ransomware) Match(ev *events.Event, st *State) *alert.Alert {
	p := st.Procs[ProcKey{ev.Tgid, ev.StartTime}]
	if p == nil || p.Alerted {
		return nil
	}
	now := time.Now()
	if now.Sub(p.ScoreStart) > r.ScoreWindow {
		p.ResetScore(now)
	}

	switch ev.Type {
	case events.EvInodeRename:
		p.RenameTimes = slide(append(p.RenameTimes, now), now, r.Window)
		if len(p.RenameTimes) >= r.RenameThreshold && !p.RenameFlagged {
			p.RenameFlagged = true
			p.Score += 2
			p.Reasons = append(p.Reasons, "rename in masa")
		}
		ext := filepath.Ext(ev.Path2)
		if ext != "" && ext != filepath.Ext(ev.Path) {
			p.NewExts[ext]++
			if p.NewExts[ext] >= r.ExtThreshold && !p.ExtFlagged {
				p.ExtFlagged = true
				p.Score += 3
				p.Reasons = append(p.Reasons, "extensie noua repetata: "+ext)
			}
		}
	case events.EvInodeUnlink:
		p.UnlinkTimes = slide(append(p.UnlinkTimes, now), now, r.Window)
		if len(p.UnlinkTimes) >= r.UnlinkThreshold && !p.UnlinkFlagged {
			p.UnlinkFlagged = true
			p.Score += 2
			p.Reasons = append(p.Reasons, "unlink in masa")
		}
	case events.EvInodeCreate:
		p.CreateTimes = slide(append(p.CreateTimes, now), now, r.Window)
		if len(p.CreateTimes) >= r.CreateThreshold && !p.CreateFlagged {
			p.CreateFlagged = true
			p.Score += 1
			p.Reasons = append(p.Reasons, "create in masa")
		}
		name := strings.ToLower(ev.Path)
		for _, k := range noteKeywords {
			if strings.Contains(name, k) && !p.NoteFlagged {
				p.NoteFlagged = true
				p.Score += 2
				p.Reasons = append(p.Reasons, "posibila nota de rascumparare: "+ev.Path)
				break
			}
		}
	case events.EvFileOpen:
		p.Dirs[filepath.Dir(ev.Path)] = struct{}{}
		if len(p.Dirs) >= r.DirThreshold && !p.DirFlagged {
			p.DirFlagged = true
			p.Score += 1
			p.Reasons = append(p.Reasons, "scrieri in multe directoare")
		}
	}

	if p.FromTmp && p.Score > 0 && !contains(p.Reasons, "proces din /tmp") {
		p.Score += 1
		p.Reasons = append(p.Reasons, "proces din /tmp")
	}

	if p.Score >= r.AlertScore {
		p.Alerted = true
		return &alert.Alert{
			Rule:     "ransomware-suspected",
			Severity: 5,
			Mitre:    "T1486",
			Tgid:     ev.Tgid,
			Ppid:     ev.Ppid,
			Comm:     ev.Comm,
			Exe:      p.ExePath,
			Detail:   fmt.Sprintf("scor %d: %s", p.Score, strings.Join(p.Reasons, "; ")),
			Time:     now,
		}
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

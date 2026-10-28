package policy

import (
	"time"
	"strings"
	"oblivion/internal/events"
)

type ProcKey struct {
	Tgid      uint32
	StartTime uint64
}

type Proc struct {
	Key      ProcKey
	Ppid     uint32
	Comm     string
	ExePath  string
	FromTmp  bool

	//ransomeware si score pentru rules compuse
	Alerted    bool
	Score      int
	Reasons    []string
	ScoreStart time.Time

	RenameTimes   []time.Time
	RenameFlagged bool
	UnlinkTimes   []time.Time
	UnlinkFlagged bool
	CreateTimes   []time.Time
	CreateFlagged bool
	NoteFlagged   bool
	NewExts       map[string]int
	ExtFlagged    bool
	Dirs          map[string]struct{}
	DirFlagged    bool
}
func (p *Proc) ResetScore(now time.Time) {
	p.ScoreStart = now
	p.Score = 0
	p.Reasons = nil
	p.RenameTimes = nil
	p.UnlinkTimes = nil
	p.CreateTimes = nil
	p.RenameFlagged = false
	p.UnlinkFlagged = false
	p.CreateFlagged = false
	p.NoteFlagged = false
	p.ExtFlagged = false
	p.DirFlagged = false
	p.NewExts = make(map[string]int)
	p.Dirs = make(map[string]struct{})
}

type State struct {
	Procs map[ProcKey]*Proc
}

func NewState() *State {
	return &State{Procs: make(map[ProcKey]*Proc)}
}

func (s *State) Update(ev *events.Event) {
	k := ProcKey{ev.Tgid, ev.StartTime}
	p, ok := s.Procs[k]
	if !ok {
		p = &Proc{Key: k, Ppid: ev.Ppid}
		p.ResetScore(time.Now())
		s.Procs[k] = p
	}
	p.Comm = ev.Comm
	if ev.Type == events.EvExec {
		p.ExePath = ev.Path
		for _, pre := range riskyPrefixes {
			if strings.HasPrefix(ev.Path, pre) {
				p.FromTmp = true
			}
		}
	}
}

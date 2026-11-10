package policy

import (
	"oblivion/internal/alert"
	"oblivion/internal/events"
	"time"
)
/*
state = memoria motorului,un eveniment rareori spune ceva,o secventa de 
evenimente pe de alta parte da
rules = lista regulilor
out = alerta ce va afi afisata pe baza regulilor incalcate


*/
type alertKey struct {
	tgid uint32
	rule string
}
type Engine struct {
	state *State
	rulesByEv 	map[events.Type][]Rule
	rules []Rule
	out   func(*alert.Alert)
	lastSeen map[alertKey]time.Time
}

func NewEngine(out func(*alert.Alert), rules ...Rule) *Engine {
	return &Engine{state: NewState(), rules: rules, out: out,lastSeen: make(map[alertKey]time.Time),}
}

func (e *Engine) Handle(ev *events.Event) {
	e.state.Update(ev)
	now := time.Now()
	for _, r := range e.rules {
		if a := r.Match(ev, e.state); a != nil {
			key := alertKey{tgid: a.Tgid, rule: a.Rule}
			if last, ok := e.lastSeen[key]; ok && now.Sub(last) < 5*time.Second {
				continue 
			}
			e.lastSeen[key] = now
			e.out(a)
		}
	}
}

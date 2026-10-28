package policy

import (
	"oblivion/internal/alert"
	"oblivion/internal/events"
)
/*
state = memoria motorului,un eveniment rareori spune ceva,o secventa de 
evenimente pe de alta parte da
rules = lista regulilor
out = alerta ce va afi afisata pe baza regulilor incalcate


*/
type Engine struct {
	state *State
	rules []Rule
	out   func(*alert.Alert)
}

func NewEngine(out func(*alert.Alert), rules ...Rule) *Engine {
	return &Engine{state: NewState(), rules: rules, out: out}
}

func (e *Engine) Handle(ev *events.Event) {
	e.state.Update(ev)
	for _, r := range e.rules {
		if a := r.Match(ev, e.state); a != nil {
			e.out(a)
		}
	}
}

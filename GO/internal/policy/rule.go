package policy

import (
	"oblivion/internal/alert"
	"oblivion/internal/events"
)

type Rule interface {
	ID() string
	Match(ev *events.Event, st *State) *alert.Alert
}

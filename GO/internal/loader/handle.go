package loader

import (
	"fmt"
	"oblivion/internal/events"
)

func handle(ev *events.Event) {
	fmt.Printf("%s tgid=%d ppid=%d comm=%s path=%s path2=%s\n",
		ev.Type, ev.Tgid, ev.Ppid, ev.Comm, ev.Path, ev.Path2)

	switch ev.Type {
	case events.EvTaskKill:
		fmt.Printf("  target_pid=%d sig=%d\n", ev.TargetPid, ev.Sig)
	case events.EvTaskFixSetuid:
		fmt.Printf("  euid %d->%d\n", ev.OldEuid, ev.NewEuid)
	case events.EvCapset:
		fmt.Printf("  added=0x%x\n", ev.CapAdded)
	case events.EvSocketConnect, events.EvSocketBind:
		fmt.Printf("  family=%d %s:%d\n", ev.Family, ev.DstIP, ev.DstPort)
	}
}

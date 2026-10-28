package loader

import (
	"net"
	"oblivion/internal/events"
)
func cstr(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
func toEvent(o *oblivionEvent) events.Event{
	ev := events.Event{
		Type:      events.Type(o.Type),
		Ts:        o.Ts,
		Tgid:      o.Tgid,
		Pid:       o.Pid,
		Ppid:      o.Ppid,
		Uid:       o.Uid,
		StartTime: o.StartTime,
		Comm:      cstr(o.Comm[:]),
		Path:      cstr(o.Path[:]),
		Path2:     cstr(o.Path2[:]),

		TargetIno:  o.Target.Ino,
		TargetDev:  o.Target.Dev,
		TargetMode: o.Target.Mode,
		ParentIno:  o.Parent.Ino,
		ParentDev:  o.Parent.Dev,
		ReqMode:    o.ReqMode,
		Flags:      o.Flags,

		Prot:   o.Prot,
		IsAnon: o.IsAnon != 0,

		OldEuid:   o.OldEuid,
		NewEuid:   o.NewEuid,
		CapAdded:  o.CapPermitted &^ o.CapOldPermitted,
		TargetPid: o.TargetPid,
		Sig:       o.Sig,

		Family:  o.Family,
		DstPort: o.Dport,
	}

	switch o.Family {
	case 2:
		ip := make(net.IP, 4)
		copy(ip, o.Daddr[:4])
		ev.DstIP = ip
	case 10:
		ip := make(net.IP, 16)
		copy(ip, o.Daddr[:])
		ev.DstIP = ip
	}
	return ev	

}

package policy

import (
	"fmt"
	"oblivion/internal/alert"
	"oblivion/internal/events"
	"path/filepath"
	"strings"
	"time"
)

type DeclarativeRule struct {
	RuleID      string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Mitre       string   `yaml:"mitre"`
	Severity    int      `yaml:"severity"`
	Events      []string `yaml:"events"`

	// Filtre pe Proces & Parinte
	Comms       []string `yaml:"comms,omitempty"`
	NotComms    []string `yaml:"not_comms,omitempty"`
	ParentComms []string `yaml:"parent_comms,omitempty"`
	FromTmp     *bool    `yaml:"from_tmp,omitempty"`
	HasNetConn  *bool    `yaml:"has_net_conn,omitempty"`

	// Filtre pe Fisiere (Path / Path2)
	PathExact    []string `yaml:"path_exact,omitempty"`
	PathPrefixes []string `yaml:"path_prefixes,omitempty"`
	PathSuffixes []string `yaml:"path_suffixes,omitempty"`
	PathContains []string `yaml:"path_contains,omitempty"`

	// Filtre pe Permisiuni, Memorie, Creds si Retea
	ModeMask     uint32   `yaml:"mode_mask,omitempty"`
	ProtMask     uint32   `yaml:"prot_mask,omitempty"`
	IsAnon       *bool    `yaml:"is_anon,omitempty"`
	RequireNonRootUid bool `yaml:"require_non_root_uid,omitempty"`
	EuidTransitionToRoot bool `yaml:"euid_transition_to_root,omitempty"`
	CapMask      uint64   `yaml:"cap_mask,omitempty"`
	DstPorts     []uint16 `yaml:"dst_ports,omitempty"`
	ExternalIP   *bool    `yaml:"external_ip,omitempty"`
}

func (r DeclarativeRule) ID() string { return r.RuleID }

func (r DeclarativeRule) Match(ev *events.Event, st *State) *alert.Alert {
	// 1. Verificare tip eveniment
	if !matchStringSlice(ev.Type.String(), r.Events) {
		return nil
	}

	p := st.Procs[ProcKey{ev.Tgid, ev.StartTime}]
	exe := ev.Path
	if p != nil && p.ExePath != "" {
		exe = p.ExePath
	}

	// 2. Filtre pe Comm si NotComms (Whitelist)
	if len(r.Comms) > 0 && !matchStringSlice(ev.Comm, r.Comms) {
		return nil
	}
	if len(r.NotComms) > 0 && matchStringSlice(ev.Comm, r.NotComms) {
		return nil
	}

	// 3. Filtre pe Parinte (Stateful)
	if len(r.ParentComms) > 0 {
		parent := st.FindParent(ev.Ppid)
		if parent == nil || !matchStringSlice(parent.Comm, r.ParentComms) {
			return nil
		}
	}

	// 4. Filtre pe starea procesului (FromTmp / HasNetConn)
	if r.FromTmp != nil && (p == nil || p.FromTmp != *r.FromTmp) {
		return nil
	}
	if r.HasNetConn != nil && (p == nil || p.HasNetConn != *r.HasNetConn) {
		return nil
	}

	// 5. Filtre pe Path (sau Path2 la rename/link)
	targetPath := ev.Path
	if ev.Type == events.EvInodeRename || ev.Type == events.EvInodeSymlink || ev.Type == events.EvInodeLink {
		if ev.Path2 != "" {
			targetPath = ev.Path2
		}
	}
	if !matchPaths(targetPath, r.PathExact, r.PathPrefixes, r.PathSuffixes, r.PathContains) {
		return nil
	}

	// 6. Filtre pe Mode, Prot, Creds, Capabilities, Retea
	if r.ModeMask != 0 && ((ev.TargetMode|ev.ReqMode)&r.ModeMask) == 0 {
		return nil
	}
	if r.ProtMask != 0 && (ev.Prot&r.ProtMask) != r.ProtMask {
		return nil
	}
	if r.IsAnon != nil && ev.IsAnon != *r.IsAnon {
		return nil
	}
	if r.RequireNonRootUid && ev.Uid == 0 {
		return nil
	}
	if r.EuidTransitionToRoot && !(ev.OldEuid != 0 && ev.NewEuid == 0) {
		return nil
	}
	if r.CapMask != 0 && (ev.CapAdded&r.CapMask) == 0 {
		return nil
	}
	if len(r.DstPorts) > 0 && !matchPortSlice(ev.DstPort, r.DstPorts) {
		return nil
	}
	if r.ExternalIP != nil && *r.ExternalIP {
		if ev.DstIP == nil || ev.DstIP.IsLoopback() || ev.DstIP.IsPrivate() {
			return nil
		}
	}

	return &alert.Alert{
		Rule:     r.RuleID,
		Severity: r.Severity,
		Mitre:    r.Mitre,
		Tgid:     ev.Tgid,
		Ppid:     ev.Ppid,
		Comm:     ev.Comm,
		Exe:      exe,
		Detail:   fmt.Sprintf("%s (comm=%s, path=%s, dst=%v:%d)", r.Name, ev.Comm, targetPath, ev.DstIP, ev.DstPort),
		Time:     time.Now(),
	}
}

func matchStringSlice(val string, list []string) bool {
	for _, item := range list {
		if item == val || filepath.Base(val) == item {
			return true
		}
	}
	return false
}

func matchPortSlice(port uint16, list []uint16) bool {
	for _, p := range list {
		if p == port {
			return true
		}
	}
	return false
}

func matchPaths(p string, exact, prefixes, suffixes, contains []string) bool {
	if len(exact) == 0 && len(prefixes) == 0 && len(suffixes) == 0 && len(contains) == 0 {
		return true
	}
	for _, e := range exact {
		if p == e {
			return true
		}
	}
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for _, suf := range suffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	for _, c := range contains {
		if strings.Contains(p, c) {
			return true
		}
	}
	return false
}
